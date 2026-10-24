//! End-to-end phase-0 check: a quinn client speaking the framed protocol
//! completes the Connect -> RequestInsecurePlayerOptions ->
//! InsecurePlayerOptions exchange against the real server endpoint.

use std::net::SocketAddr;
use std::sync::Arc;

use rustale_protocol::packets::ids;
use rustale_protocol::{encode_frame, Connect, FrameDecoder, InsecurePlayerOptions};

// Ignored in sandboxed environments that block UDP sockets entirely
// (this dev VM does: even loopback UDP sendto returns EPERM). On a normal
// machine, run with: cargo test -- --ignored
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires working UDP sockets"]
async fn offline_identification_exchange() {
    let bundle = rustale_server::build_server(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    let server_addr = bundle.local_addr;
    let server_cert = bundle.server_cert.clone();
    // This test exercises the insecure development handshake.
    std::env::set_var("RUSTALE_AUTH_MODE", "offline");
    let server_cert2 = bundle.server_cert.clone();
    let server = tokio::spawn(async move { rustale_server::serve(bundle.endpoint, &server_cert2).await });

    // Client endpoint trusting exactly the server's certificate.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(server_cert).unwrap();
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![rustale_protocol::packets::ALPN.to_vec()];
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let mut client = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    client.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic)));

    let conn = client.connect(server_addr, "localhost").unwrap().await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();

    // Send Connect.
    let connect = Connect {
        protocol_crc: rustale_protocol::packets::PROTOCOL_CRC,
        protocol_build_number: rustale_protocol::packets::PROTOCOL_BUILD_NUMBER,
        client_version: "1.0.0".to_string(),
        client_type: 0,
        identity_token: None,
        language: "en-US".to_string(),
        referral_data: None,
        referral_source: None,
    };
    send.write_all(&encode_frame(ids::CONNECT, &connect.serialize().unwrap())).await.unwrap();

    // Expect RequestInsecurePlayerOptions (id 364, empty payload).
    let mut decoder = FrameDecoder::new();
    let mut buf = vec![0u8; 4096];
    let (packet_id, payload) = loop {
        let n = recv.read(&mut buf).await.unwrap().unwrap();
        decoder.feed(&buf[..n]);
        if let Some(frame) = decoder.next_frame().unwrap() {
            break frame;
        }
    };
    assert_eq!(packet_id, ids::REQUEST_INSECURE_PLAYER_OPTIONS);
    assert!(payload.is_empty());

    // Answer with our identity.
    let opts = InsecurePlayerOptions {
        uuid: [0xAB; 16],
        username: "Cross".to_string(),
        skin_raw: None,
    };
    send.write_all(&encode_frame(ids::INSECURE_PLAYER_OPTIONS, &opts.serialize().unwrap()))
        .await
        .unwrap();
    send.finish().unwrap();

    // Give the server a moment to process, then shut down.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    conn.close(quinn::VarInt::from_u32(0), b"done");
    client.wait_idle().await;
    server.abort();
}
