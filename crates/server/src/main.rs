use std::net::SocketAddr;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let port: u16 = std::env::var("HYTALE_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5520);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let bundle = hytale_server::build_server(addr)?;
    println!("[server] listening on UDP {} (protocol build {})", bundle.local_addr, hytale_protocol::packets::PROTOCOL_BUILD_NUMBER);
    hytale_server::serve(bundle.endpoint).await;
    Ok(())
}
