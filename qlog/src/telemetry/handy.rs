use std::{
    io,
    path::{Path, PathBuf},
    sync::Arc,
};

use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    sync::mpsc,
};

use super::{ExportEvent, Log, Span};
use crate::{Event, GroupID, QlogFileSeq, VantagePoint, VantagePointType};

pub struct NullExporter;

impl ExportEvent for NullExporter {
    fn emit(&self, event: Event) {
        _ = event;
    }
}

pub struct IoExpoter(mpsc::UnboundedSender<Event>);

impl IoExpoter {
    pub fn new<O>(qlog_file_seq: QlogFileSeq, mut output: O) -> Self
    where
        O: AsyncWrite + Unpin + Send + 'static,
    {
        let (tx, mut rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let task = async {
                const RS: u8 = 0x1E;

                output.write_u8(RS).await?;
                let qlog_file_seq = serde_json::to_string(&qlog_file_seq).unwrap();
                output.write_all(qlog_file_seq.as_bytes()).await?;
                output.write_u8(b'\n').await?;

                while let Some(event) = rx.recv().await {
                    let event = serde_json::to_string(&event).unwrap();
                    output.write_u8(RS).await?;
                    output.write_all(event.as_bytes()).await?;
                    output.write_u8(b'\n').await?;
                }

                io::Result::Ok(())
            };
            if let Err(error) = task.await {
                tracing::error!(
                    ?error,
                    ?qlog_file_seq,
                    "failed to write qlog, subsequent qlogs in this exporter will be ignored."
                );
            }
        });
        Self(tx)
    }
}

impl ExportEvent for IoExpoter {
    fn emit(&self, event: Event) {
        _ = self.0.send(event);
    }
}

pub struct NullLogger;

impl Log for NullLogger {
    #[inline]
    fn new_trace(&self, _: VantagePointType, _: GroupID) -> Span {
        Span::new(Arc::new(NullExporter), Default::default())
    }
}

impl<L: Log + ?Sized> Log for Arc<L> {
    #[inline]
    fn new_trace(&self, vantage_point: VantagePointType, group_id: GroupID) -> Span {
        self.as_ref().new_trace(vantage_point, group_id)
    }
}

pub trait TelemetryStorage {
    fn join(
        &self,
        file_name: &str,
    ) -> impl Future<Output = impl AsyncWrite + Send + Unpin + 'static> + Send + 'static;
}

impl TelemetryStorage for PathBuf {
    fn join(
        &self,
        file_name: &str,
    ) -> impl Future<Output = impl AsyncWrite + Send + Unpin + 'static> + Send + 'static {
        let file_path = Path::join(self, file_name);
        async move {
            tokio::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(file_path)
                .await
                .unwrap()
        }
    }
}

pub struct DefaultSeqLogger<S> {
    storage: S,
}

impl<S: Clone> Clone for DefaultSeqLogger<S> {
    fn clone(&self) -> Self {
        Self {
            storage: self.storage.clone(),
        }
    }
}

impl<S> DefaultSeqLogger<S> {
    pub fn new(storage: S) -> Self {
        Self { storage }
    }
}

impl<S: TelemetryStorage> Log for DefaultSeqLogger<S> {
    fn new_trace(&self, vantage_point: VantagePointType, group_id: GroupID) -> Span {
        use crate::legacy;

        let file_name = format!("{group_id}_{}.sqlog", vantage_point);
        let file = self.storage.join(&file_name);

        let qlog_file_seq = crate::build!(legacy::QlogFileSeq {
            title: file_name,
            trace: legacy::TraceSeq {
                vantage_point: VantagePoint {
                    r#type: vantage_point
                },
            }
        });

        let (tx, mut rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut log_file = file.await;

            const RS: u8 = 0x1E;

            log_file.write_u8(RS).await?;
            let qlog_file_seq = serde_json::to_string(&qlog_file_seq).unwrap();
            log_file.write_all(qlog_file_seq.as_bytes()).await?;
            log_file.write_u8(b'\n').await?;

            while let Some(event) = rx.recv().await {
                let Ok(event) = legacy::Event::try_from(event) else {
                    continue;
                };
                let event = serde_json::to_string(&event).unwrap();
                log_file.write_u8(RS).await?;
                log_file.write_all(event.as_bytes()).await?;
                log_file.write_u8(b'\n').await?;
            }

            io::Result::Ok(())
        });

        crate::span!(Arc::new(IoExpoter(tx)), group_id = group_id)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{
        LogFile, TraceSeq, VantagePoint, VantagePointType,
        quic::connectivity::ServerListening,
        telemetry::{Instrument, Span},
    };

    #[tokio::test]
    async fn io_exporter() {
        let exporter = IoExpoter::new(
            crate::build!(QlogFileSeq {
                log_file: LogFile {
                    title: "io exporter example",
                    file_schema: QlogFileSeq::SCHEMA,
                    serialization_format: "application/qlog+json-seq",
                },
                trace_seq: TraceSeq {
                    title: "io exporter example",
                    description: "just a example",
                    vantage_point: VantagePoint {
                        r#type: VantagePointType::Unknow,
                    },
                }
            }),
            tokio::io::stdout(),
        );

        let meaningless_field = 112233u64;
        crate::span!(Arc::new(exporter), meaningless_field).in_scope(|| {
            crate::event!(ServerListening {
                ip_v4: "127.0.0.1".to_owned(),
                port_v4: 443u16
            });

            tokio::spawn(
                async move {
                    assert_eq!(Span::current().load::<String>("path_id"), "new path");
                    assert_eq!(Span::current().load::<u64>("meaningless_field"), 112233u64);
                    // do something
                }
                .instrument(crate::span!(@current, path_id = String::from("new path"))),
            );
        });

        tokio::task::yield_now().await;
    }
}
