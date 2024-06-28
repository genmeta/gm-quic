use qbase::{
    config::TransportParameters,
    packet::keys::{ArcKeys, ArcOneRttKeys},
};
use qrecovery::crypto::{CryptoStreamReader, CryptoStreamWriter};
use rustls::quic::KeyChange;

use crate::crypto::TlsIO;

async fn exchange_hs(
    tls_session: &TlsIO,
    (stream_reader, stream_writer): (CryptoStreamReader, CryptoStreamWriter),
) -> std::io::Result<KeyChange> {
    let (tls_reader, tls_writer) = tls_session.split_io();
    let loop_read = tls_reader.loop_read_from(stream_reader);
    let mut poll_writer = tls_writer.write_to(stream_writer);
    let key_change = poll_writer.loop_write().await?;
    loop_read.end().await?;
    Ok(key_change)
}

pub(crate) async fn exchange_initial_crypto_msg_until_getting_handshake_key(
    tls_session: TlsIO,
    handshake_keys: ArcKeys,
    initial_crypto_handler: (CryptoStreamReader, CryptoStreamWriter),
) {
    match exchange_hs(&tls_session, initial_crypto_handler).await {
        Ok(key_change) => match key_change {
            KeyChange::Handshake { keys } => {
                handshake_keys.set_keys(keys);
            }
            _ => unreachable!(),
        },
        Err(_) => {
            todo!()
        }
    }
}

pub(crate) async fn exchange_handshake_crypto_msg_until_getting_1rtt_key(
    tls_session: TlsIO,
    one_rtt_keys: ArcOneRttKeys,
    handshake_crypto_handler: (CryptoStreamReader, CryptoStreamWriter),
) -> TransportParameters {
    match exchange_hs(&tls_session, handshake_crypto_handler).await {
        Ok(key_change) => match key_change {
            KeyChange::OneRtt { keys, next } => {
                one_rtt_keys.set_keys(keys, next);

                tls_session.get_transport_parameters().unwrap()
            }
            _ => unreachable!(),
        },
        Err(_) => {
            todo!()
        }
    }
}
