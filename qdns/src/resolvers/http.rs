use std::{collections::HashMap, fmt::Display, io};

use dashmap::DashMap;
use gmdns::{MdnsPacket, parser::packet::be_packet};
use qbase::net::route::SocketEndpointAddr;
use reqwest::{Client, IntoUrl, StatusCode, Url};
use rustls::{SignatureScheme, sign::SigningKey};
use tokio::time::Instant;

use crate::{Resolve, to_endpoint_addr, to_signed_mdns_ep};

#[derive(Debug)]
struct Record {
    addrs: Vec<SocketEndpointAddr>,
    expire: Instant,
}

#[derive(Debug)]
pub struct HttpResolver {
    http_client: Client,
    base_url: Url,
    cached_records: DashMap<String, Record>,
}

impl Display for HttpResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Http DNS({})",
            self.base_url.host_str().expect("Cheked in constructor")
        )
    }
}

impl HttpResolver {
    pub fn new(base_url: impl IntoUrl) -> io::Result<Self> {
        let base_url = base_url
            .into_url()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        base_url.host_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Base URL must have a valid host",
            )
        })?;

        let http_client = Client::builder()
            .build()
            // with certs?
            .expect("Failed to build HTTP client");
        Ok(Self {
            http_client,
            base_url,
            cached_records: DashMap::new(),
        })
    }
}

#[derive(thiserror::Error, Debug)]
enum Error {
    #[error(transparent)]
    Reqwest { source: reqwest::Error },

    #[error("{status}")]
    Status { status: StatusCode },

    #[error("No dns record found")]
    NoRecordFound {},

    #[error("Failed to parse dns records from response")]
    ParseRecords { source: io::Error },
}

impl From<reqwest::Error> for Error {
    fn from(source: reqwest::Error) -> Self {
        match source.status() {
            Some(stateus) if stateus == StatusCode::NOT_FOUND => Error::NoRecordFound {},
            Some(status) => Error::Status { status },
            None => Error::Reqwest {
                source: source.without_url(),
            },
        }
    }
}

#[async_trait::async_trait]
impl Resolve for HttpResolver {
    async fn publish(
        &self,
        name: &str,
        is_main: bool,
        sequence: u64,
        key: Option<(&dyn SigningKey, SignatureScheme)>,
        addresses: &[SocketEndpointAddr],
    ) -> io::Result<()> {
        let publish = async {
            tracing::debug!(name, ?addresses, "Publishing DNS for with addresses");
            let dns_eps = addresses
                .iter()
                .filter_map(|addr| to_signed_mdns_ep(*addr, is_main, sequence, key).ok())
                .collect::<Vec<_>>();
            let mut hosts = HashMap::new();

            hosts.insert(name.to_string(), dns_eps);
            let answer = MdnsPacket::answer(0, &hosts);
            let bytes = answer.to_bytes();

            let mut url = self.base_url.join("publish").expect("Invalid base URL");
            url.set_query(Some(&format!("host={name}")));
            let client = reqwest::Client::new();
            let response = client
                .post(url)
                .header("Content-Type", "application/octet-stream")
                .body(bytes)
                .send()
                .await;

            let _response = response?.error_for_status()?;
            Result::<_, Error>::Ok(())
        };
        publish.await.map_err(io::Error::other)
    }

    async fn lookup(&self, name: &str) -> io::Result<Vec<SocketEndpointAddr>> {
        let lookup = async {
            use gmdns::parser::record;
            let now = Instant::now();
            self.cached_records
                .retain(|_host, Record { expire, .. }| *expire < now);
            if let Some(record) = self.cached_records.get(name) {
                return Ok(record.addrs.clone());
            }
            let mut url = self.base_url.join("lookup").expect("Invalid URL");
            url.query_pairs_mut().append_pair("host", name);
            let response = self.http_client.get(url).send().await;

            let response = response?.error_for_status()?.bytes().await?;

            let (_remain, packet) = be_packet(&response).map_err(|error| Error::ParseRecords {
                source: io::Error::other(error.to_string()),
            })?;

            let ret = packet
                .answers
                .iter()
                .filter_map(|answer| match answer.data() {
                    record::RData::E(e) => Some(to_endpoint_addr(e)),
                    _ => {
                        tracing::debug!(?answer, "Ignored record");
                        None
                    }
                })
                .collect::<Vec<_>>();
            if ret.is_empty() {
                return Err(Error::NoRecordFound {});
            }

            Result::<_, Error>::Ok(ret)
        };
        lookup.await.map_err(io::Error::other)
    }
}
