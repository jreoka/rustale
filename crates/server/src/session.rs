//! Transport-independent connection state machine: consumes decoded
//! packets, produces framed replies and close decisions. The QUIC layer is
//! a thin adapter around this, which also makes the whole login exchange
//! testable without a live UDP socket.

use hytale_protocol::packets::ids;
use hytale_protocol::{encode_frame, Connect, InsecurePlayerOptions};

use crate::close_code;

#[derive(Default, PartialEq, Clone, Copy, Debug)]
pub enum Phase {
    #[default]
    AwaitConnect,
    AwaitIdentity,
    Identified,
}

#[derive(Default)]
pub struct SessionOutcome {
    /// Complete frames ready to write to the client's stream.
    pub frames: Vec<Vec<u8>>,
    /// If set, close the connection with this QUIC application error code.
    pub close: Option<u32>,
    /// If true, drop this stream (protocol violation).
    pub drop_stream: bool,
}

#[derive(Default)]
pub struct Session {
    phase: Phase,
}

impl Session {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn handle(&mut self, packet_id: i32, payload: &[u8]) -> SessionOutcome {
        let mut out = SessionOutcome::default();
        match packet_id {
            ids::CONNECT => match Connect::deserialize(payload) {
                Ok(connect) => {
                    println!(
                        "[server] Connect: crc={} build={} version={:?} type={} lang={:?} token={}",
                        connect.protocol_crc,
                        connect.protocol_build_number,
                        connect.client_version,
                        connect.client_type,
                        connect.language,
                        if connect.identity_token.is_some() { "present" } else { "absent" },
                    );
                    if connect.protocol_crc != hytale_protocol::packets::PROTOCOL_CRC
                        || connect.protocol_build_number
                            != hytale_protocol::packets::PROTOCOL_BUILD_NUMBER
                    {
                        eprintln!("[server] protocol mismatch, closing with InvalidVersion");
                        out.close = Some(close_code::INVALID_VERSION);
                        return out;
                    }
                    // Offline mode: we hold no session credentials, so ask
                    // the client to identify itself the insecure way.
                    out.frames.push(encode_frame(ids::REQUEST_INSECURE_PLAYER_OPTIONS, &[]));
                    self.phase = Phase::AwaitIdentity;
                }
                Err(e) => {
                    eprintln!("[server] undecodable Connect: {e}");
                    out.drop_stream = true;
                }
            },
            ids::INSECURE_PLAYER_OPTIONS => match InsecurePlayerOptions::deserialize(payload) {
                Ok(opts) => {
                    println!(
                        "[server] InsecurePlayerOptions: uuid={} username={:?} skin={}",
                        crate::format_uuid(&opts.uuid),
                        opts.username,
                        if opts.skin_raw.is_some() { "present" } else { "absent" },
                    );
                    self.phase = Phase::Identified;
                }
                Err(e) => {
                    eprintln!("[server] undecodable InsecurePlayerOptions: {e}");
                }
            },
            ids::CLIENT_DISCONNECT => {
                println!("[server] client disconnect packet");
                out.drop_stream = true;
            }
            other => {
                println!(
                    "[server] packet id={other} ({} bytes) phase={:?}",
                    payload.len(),
                    self.phase
                );
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hytale_protocol::FrameDecoder;

    fn connect_bytes() -> Vec<u8> {
        Connect {
            protocol_crc: hytale_protocol::packets::PROTOCOL_CRC,
            protocol_build_number: hytale_protocol::packets::PROTOCOL_BUILD_NUMBER,
            client_version: "1.0.0".to_string(),
            client_type: 0,
            identity_token: None,
            language: "en-US".to_string(),
            referral_data: None,
            referral_source: None,
        }
        .serialize()
        .unwrap()
    }

    #[test]
    fn full_offline_exchange() {
        let mut session = Session::new();
        let out = session.handle(ids::CONNECT, &connect_bytes());
        assert!(out.close.is_none());
        assert_eq!(out.frames.len(), 1);
        // The reply frame must decode as packet 364 with an empty payload.
        let mut dec = FrameDecoder::new();
        dec.feed(&out.frames[0]);
        let (id, payload) = dec.next_frame().unwrap().unwrap();
        assert_eq!(id, ids::REQUEST_INSECURE_PLAYER_OPTIONS);
        assert!(payload.is_empty());
        assert_eq!(session.phase(), Phase::AwaitIdentity);

        let opts = InsecurePlayerOptions {
            uuid: [0xAB; 16],
            username: "Cross".to_string(),
            skin_raw: None,
        };
        let out = session.handle(ids::INSECURE_PLAYER_OPTIONS, &opts.serialize().unwrap());
        assert!(out.frames.is_empty());
        assert_eq!(session.phase(), Phase::Identified);
    }

    #[test]
    fn wrong_protocol_version_closes() {
        let mut bad = Connect {
            protocol_crc: 1234,
            protocol_build_number: 1,
            client_version: "0.0.1".to_string(),
            client_type: 0,
            identity_token: None,
            language: "en-US".to_string(),
            referral_data: None,
            referral_source: None,
        };
        let bytes = bad.serialize().unwrap();
        let mut session = Session::new();
        let out = session.handle(ids::CONNECT, &bytes);
        assert_eq!(out.close, Some(close_code::INVALID_VERSION));
        bad.protocol_crc = hytale_protocol::packets::PROTOCOL_CRC;
        let _ = bad;
    }
}
