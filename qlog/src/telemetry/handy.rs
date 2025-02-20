use std::io;

use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    sync::mpsc,
};

use super::ExportEvent;
use crate::{Event, QlogFileSeq};

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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{
        quic::connectivity::ServerListening,
        telemetry::{Instrument, Span},
        LogFile, TraceSeq, VantagePoint, VantagePointType,
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
