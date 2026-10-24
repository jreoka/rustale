# Rustale

A from-scratch Rust implementation of the Hytale dedicated server,
targeting the **release** patchline protocol (build 258, CRC 3908406161).
Written from the official shared-source protocol definitions; contains no
Hypixel code or assets. Goal: a server light enough to host a few friends
on cheap hardware, where the Java server needs 4 GB+ of RAM.

No Java plugin support is planned (by design — the target use is a small
vanilla server).

## Status: phase 0

- `crates/protocol` — wire codec: canonical varints, fixed+variable block
  packet layout, `[len][id][payload]` stream framing. Byte-exact against
  reference vectors derived from the generated serializers.
- `crates/server` — QUIC listener (quinn, ALPN `hytale/3`, UDP 5520):
  validates the `Connect` packet's protocol CRC/build (mismatch closes
  with the InvalidVersion application error), then runs the offline
  identification exchange (`RequestInsecurePlayerOptions` /
  `InsecurePlayerOptions`). All decisions live in a transport-independent
  `Session` state machine.

Not yet: ConnectAccept + setup/asset sync, chunks/world, movement,
gameplay.

## Run

```
cargo run --release -p rustale-server   # listens on UDP 5520 (HYTALE_PORT to override)
cargo test                             # protocol + session tests
cargo test -- --ignored                # live QUIC handshake test (needs UDP)
```

Note: the dev sandbox this was written in blocks UDP sockets entirely,
so the live handshake test is `#[ignore]`d there; it runs anywhere else.
