//! Minimal Hytale-compatible server: QUIC listener speaking the release
//! protocol (build 258). Phase 0 scope: accept a connection, validate the
//! Connect packet, run the offline (insecure) identification exchange, and
//! log what the client sends next. No world, no gameplay yet.
//!
//! All protocol decisions live in `session::Session`; this file is only
//! the QUIC adapter around it.

pub mod session;

use std::net::SocketAddr;
use std::sync::Arc;

use hytale_protocol::{decode_packet_payload, encode_packet_frame, FrameDecoder};
use quinn::{Endpoint, VarInt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use session::Session;

/// QUIC application error codes from the protocol definitions.
pub mod close_code {
    pub const NO_ERROR: u32 = 0;
    pub const AUTH_FAILED: u32 = 2;
    pub const INVALID_VERSION: u32 = 3;
}

pub struct ServerBundle {
    pub endpoint: Endpoint,
    pub server_cert: CertificateDer<'static>,
    pub local_addr: SocketAddr,
}

/// Build a QUIC endpoint with a fresh self-signed certificate and the
/// Hytale ALPN. (How the real client treats self-signed certs in offline
/// mode is a milestone-1 test question; the reference server likewise
/// presents its own certificate.)
pub fn build_server(addr: SocketAddr) -> std::io::Result<ServerBundle> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(std::io::Error::other)?;
    let cert_der = certified.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());

    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .map_err(std::io::Error::other)?;
    tls.alpn_protocols = vec![hytale_protocol::packets::ALPN.to_vec()];

    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(std::io::Error::other)?;
    let config = quinn::ServerConfig::with_crypto(Arc::new(quic));
    let endpoint = Endpoint::server(config, addr)?;
    let local_addr = endpoint.local_addr()?;
    Ok(ServerBundle { endpoint, server_cert: cert_der, local_addr })
}

/// Accept connections until the endpoint is closed.
pub async fn serve(endpoint: Endpoint) {
    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    println!("[server] connection from {}", conn.remote_address());
                    handle_connection(conn).await;
                }
                Err(e) => eprintln!("[server] connection failed: {e}"),
            }
        });
    }
}

async fn handle_connection(conn: quinn::Connection) {
    let session = Arc::new(tokio::sync::Mutex::new(Session::new()));
    while let Ok((send, recv)) = conn.accept_bi().await {
        let session = session.clone();
        let conn = conn.clone();
        tokio::spawn(async move {
            handle_stream(conn, send, recv, session).await;
        });
    }
}

async fn handle_stream(
    conn: quinn::Connection,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    session: Arc<tokio::sync::Mutex<Session>>,
) {
    let mut decoder = FrameDecoder::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match recv.read(&mut buf).await {
            Ok(Some(n)) => {
                decoder.feed(&buf[..n]);
                loop {
                    match decoder.next_frame() {
                        Ok(Some((packet_id, raw_payload))) => {
                            let payload = match decode_packet_payload(packet_id, &raw_payload) {
                                Ok(p) => p,
                                Err(e) => {
                                    eprintln!("[server] payload decode failed for {packet_id}: {e}");
                                    return;
                                }
                            };
                            let outcome = session.lock().await.handle(packet_id, &payload);
                            for (out_id, out_payload) in &outcome.packets {
                                let frame = encode_packet_frame(*out_id, out_payload);
                                if let Err(e) = send.write_all(&frame).await {
                                    eprintln!("[server] write failed: {e}");
                                    return;
                                }
                            }
                            if let Some(code) = outcome.close {
                                conn.close(VarInt::from_u32(code), b"closed by server");
                                return;
                            }
                            if outcome.drop_stream {
                                return;
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            eprintln!("[server] frame error: {e}");
                            return;
                        }
                    }
                }
            }
            Ok(None) => return,
            Err(e) => {
                eprintln!("[server] stream read error: {e}");
                return;
            }
        }
    }
}

pub fn format_uuid(uuid: &[u8; 16]) -> String {
    let h = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    format!(
        "{}-{}-{}-{}-{}",
        h(&uuid[0..4]),
        h(&uuid[4..6]),
        h(&uuid[6..8]),
        h(&uuid[8..10]),
        h(&uuid[10..16])
    )
}
