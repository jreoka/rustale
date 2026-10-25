//! Minimal Hytale-compatible server: QUIC listener speaking the release
//! protocol (build 258). Phase 0 scope: accept a connection, validate the
//! Connect packet, run the offline (insecure) identification exchange, and
//! log what the client sends next. No world, no gameplay yet.
//!
//! All protocol decisions live in `session::Session`; this file is only
//! the QUIC adapter around it.

pub mod auth;
pub mod session;

use std::net::SocketAddr;
use std::sync::Arc;

use rustale_protocol::{decode_packet_payload, encode_packet_frame, FrameDecoder};
use quinn::{Endpoint, VarInt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use auth::{Endpoints, JwtValidator, ServerAuth};
use session::{AuthEffect, Phase, Session, SessionAuthCtx};

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
    tls.alpn_protocols = vec![rustale_protocol::packets::ALPN.to_vec()];

    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(std::io::Error::other)?;
    let config = quinn::ServerConfig::with_crypto(Arc::new(quic));
    let endpoint = Endpoint::server(config, addr)?;
    let local_addr = endpoint.local_addr()?;
    Ok(ServerBundle { endpoint, server_cert: cert_der, local_addr })
}

/// Everything the authenticated login exchange needs at runtime.
pub struct AuthRuntime {
    server_auth: Arc<ServerAuth>,
    validator: Arc<JwtValidator>,
    http: reqwest::Client,
    sessions_url: String,
    cert_fingerprint: String,
}

/// Build the auth runtime unless RUSTALE_AUTH_MODE=offline (the insecure
/// development handshake, which the retail client refuses). May run the
/// interactive device login on first use; returns None on offline mode,
/// and aborts startup on auth failure — an authenticated server without
/// a session can only fail every connection anyway.
async fn build_auth_runtime(cert_der: &[u8]) -> Option<Arc<AuthRuntime>> {
    if std::env::var("RUSTALE_AUTH_MODE").map(|v| v.to_lowercase()) == Ok("offline".to_string()) {
        println!("[auth] RUSTALE_AUTH_MODE=offline: insecure development handshake (retail clients will refuse)");
        return None;
    }
    let domain = std::env::var("HYTALE_DOMAIN").unwrap_or_else(|_| "hytale.com".to_string());
    let endpoints = Endpoints::for_domain(&domain);
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .expect("reqwest client");
    // Default the credentials file next to the executable, not the
    // working directory, so restarts find it no matter where the server
    // is launched from. RUSTALE_AUTH_FILE overrides.
    let auth_file = match std::env::var("RUSTALE_AUTH_FILE") {
        Ok(p) => p.into(),
        Err(_) => std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|dir| dir.join("auth.json")))
            .unwrap_or_else(|| "auth.json".into()),
    };
    println!("[auth] credentials file: {}", auth_file.display());
    let server_auth = match ServerAuth::init(http.clone(), endpoints.clone(), Some(auth_file)).await {
        Ok(a) => Arc::new(a),
        Err(e) => {
            eprintln!("[auth] FATAL: could not establish the server session: {e}");
            eprintln!("[auth] (delete auth.json to redo the login, or set RUSTALE_AUTH_MODE=offline for development clients)");
            std::process::exit(1);
        }
    };
    let validator = Arc::new(JwtValidator::new(endpoints.issuer().to_string()));
    validator.maybe_refresh(&http, &endpoints.sessions).await;
    println!("[auth] authenticated mode ready (server session id {})", server_auth.server_session_id);
    Some(Arc::new(AuthRuntime {
        server_auth,
        validator,
        http,
        sessions_url: endpoints.sessions.clone(),
        cert_fingerprint: auth::cert_fingerprint(cert_der),
    }))
}

/// Accept connections until the endpoint is closed.
pub async fn serve(endpoint: Endpoint, server_cert: &CertificateDer<'static>) {
    let runtime = build_auth_runtime(server_cert.as_ref()).await;
    while let Some(incoming) = endpoint.accept().await {
        let runtime = runtime.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    println!("[server] connection from {}", conn.remote_address());
                    handle_connection(conn, runtime).await;
                }
                Err(e) => eprintln!("[server] connection failed: {e}"),
            }
        });
    }
}

/// Server->client auxiliary streams, identified by their QUIC stream IDs
/// exactly as in the reference transport: the first server-initiated uni
/// stream is Chunks (id 3), the second is WorldMap (id 7). We only ever
/// open Chunks.
#[derive(Default)]
struct AuxStreams {
    chunks: Option<quinn::SendStream>,
}

async fn handle_connection(conn: quinn::Connection, runtime: Option<Arc<AuthRuntime>>) {
    let session = match &runtime {
        Some(rt) => {
            // Keep the JWKS reasonably fresh for this connection.
            rt.validator.maybe_refresh(&rt.http, &rt.sessions_url).await;
            let ctx = Arc::new(SessionAuthCtx {
                validator: rt.validator.clone(),
                audience: rt.server_auth.server_session_id.clone(),
                server_identity_token: rt.server_auth.identity_token().unwrap_or_default(),
            });
            Arc::new(tokio::sync::Mutex::new(Session::with_auth(ctx)))
        }
        None => Arc::new(tokio::sync::Mutex::new(Session::new())),
    };
    let aux = Arc::new(tokio::sync::Mutex::new(AuxStreams::default()));
    while let Ok((send, recv)) = conn.accept_bi().await {
        let session = session.clone();
        let aux = aux.clone();
        let conn = conn.clone();
        let runtime = runtime.clone();
        tokio::spawn(async move {
            handle_stream(conn, send, recv, session, aux, runtime).await;
        });
    }
}

/// Write one outcome's packets (and chunk packets) and apply its close
/// decisions. Returns false when the stream handler should stop.
async fn apply_outcome(
    conn: &quinn::Connection,
    send: &mut quinn::SendStream,
    aux: &Arc<tokio::sync::Mutex<AuxStreams>>,
    outcome: &session::SessionOutcome,
) -> bool {
    // Optional pacing knob: hold the join burst for
    // RUSTALE_JOIN_DELAY_MS before writing it (default off). It was a
    // crash diagnostic — the client died in its setup-complete
    // continuation, which turned out to be the empty ItemCategories
    // tree, not a race — and is kept only for future bisection.
    if outcome.packets.iter().any(|(id, _)| *id == rustale_protocol::packets::ids::JOIN_WORLD) {
        let delay_ms: u64 = std::env::var("RUSTALE_JOIN_DELAY_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        if delay_ms > 0 {
            println!("[server] holding join burst for {delay_ms}ms");
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        }
    }
    for (out_id, out_payload) in &outcome.packets {
        let frame = encode_packet_frame(*out_id, out_payload);
        if let Err(e) = send.write_all(&frame).await {
            eprintln!("[server] write failed: {e}");
            return false;
        }
    }
    if !outcome.chunk_packets.is_empty() {
        let mut aux = aux.lock().await;
        if aux.chunks.is_none() {
            match conn.open_uni().await {
                Ok(stream) => aux.chunks = Some(stream),
                Err(e) => {
                    eprintln!("[server] cannot open chunks stream: {e}");
                    return false;
                }
            }
        }
        let chunks = aux.chunks.as_mut().unwrap();
        for (out_id, out_payload) in &outcome.chunk_packets {
            let frame = encode_packet_frame(*out_id, out_payload);
            if let Err(e) = chunks.write_all(&frame).await {
                eprintln!("[server] chunks write failed: {e}");
                return false;
            }
        }
    }
    if let Some(code) = outcome.close {
        conn.close(VarInt::from_u32(code), b"closed by server");
        return false;
    }
    !outcome.drop_stream
}

async fn handle_stream(
    conn: quinn::Connection,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    session: Arc<tokio::sync::Mutex<Session>>,
    aux: Arc<tokio::sync::Mutex<AuxStreams>>,
    runtime: Option<Arc<AuthRuntime>>,
) {
    let mut decoder = FrameDecoder::new();
    let mut buf = vec![0u8; 64 * 1024];
    // The reference world's NetworkTickSystem writes a NetworkTick (5)
    // to every in-world player each tick (tickDurationMicros u32,
    // serverTick u32). The client's world only advances — processing
    // received chunks and entities — on these ticks; without them it
    // sits on the loading screen forever.
    let mut tick_interval = tokio::time::interval(std::time::Duration::from_millis(33));
    tick_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut server_tick: u32 = 0;
    loop {
        let read_result = tokio::select! {
            _ = tick_interval.tick() => {
                if session.lock().await.phase() == Phase::InWorld {
                    server_tick += 1;
                    let mut payload = Vec::with_capacity(8);
                    payload.extend_from_slice(&33_333u32.to_le_bytes());
                    payload.extend_from_slice(&server_tick.to_le_bytes());
                    let frame = encode_packet_frame(
                        rustale_protocol::packets::ids::NETWORK_TICK,
                        &payload,
                    );
                    if let Err(e) = send.write_all(&frame).await {
                        eprintln!("[server] tick write failed: {e}");
                        return;
                    }
                }
                continue;
            }
            read = recv.read(&mut buf) => read,
        };
        match read_result {
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
                            let mut outcome = session.lock().await.handle(packet_id, &payload);
                            // Auth side effects (session-service HTTP) run
                            // inline; each follow-up outcome is applied the
                            // same way until no effect remains.
                            loop {
                                if !apply_outcome(&conn, &mut send, &aux, &outcome).await {
                                    return;
                                }
                                match outcome.effect.take() {
                                    None => break,
                                    Some(AuthEffect::RequestGrant { identity_token }) => {
                                        let Some(rt) = &runtime else { return };
                                        let grant = match rt
                                            .server_auth
                                            .request_auth_grant(&identity_token)
                                            .await
                                        {
                                            Ok(g) => Some(g),
                                            Err(e) => {
                                                eprintln!("[auth] auth-grant request failed: {e}");
                                                None
                                            }
                                        };
                                        outcome = session.lock().await.on_auth_grant(grant);
                                    }
                                    Some(AuthEffect::ExchangeGrant { grant }) => {
                                        let Some(rt) = &runtime else { return };
                                        let token = match rt
                                            .server_auth
                                            .exchange_server_grant(&grant, &rt.cert_fingerprint)
                                            .await
                                        {
                                            Ok(t) => Some(t),
                                            Err(e) => {
                                                eprintln!("[auth] grant exchange failed: {e}");
                                                None
                                            }
                                        };
                                        outcome = session.lock().await.on_server_token(token);
                                    }
                                }
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
