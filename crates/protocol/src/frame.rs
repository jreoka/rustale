//! Stream framing, as in the reference QuicheChannel: each frame on a QUIC
//! stream is [i32 LE length][i32 LE packet id][payload], where the length
//! counts the packet-id field plus the payload (frame total = length + 4).

use crate::io::{ProtoError, Result};

/// Largest accepted frame body (packet id + payload). Individual packets
/// enforce their own smaller MaxSize during deserialization.
pub const MAX_FRAME_BODY: usize = 64 * 1024 * 1024;

pub fn encode_frame(packet_id: i32, payload: &[u8]) -> Vec<u8> {
    let body_len = 4 + payload.len();
    let mut out = Vec::with_capacity(4 + body_len);
    out.extend_from_slice(&(body_len as i32).to_le_bytes());
    out.extend_from_slice(&packet_id.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// Incremental decoder for a byte stream of frames; tolerates arbitrary
/// chunking of the underlying QUIC stream reads.
#[derive(Default)]
pub struct FrameDecoder {
    buf: Vec<u8>,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Pop the next complete frame, if one is buffered.
    pub fn next_frame(&mut self) -> Result<Option<(i32, Vec<u8>)>> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let body_len = i32::from_le_bytes(self.buf[0..4].try_into().unwrap());
        if body_len < 4 || body_len as usize > MAX_FRAME_BODY {
            return Err(ProtoError::FrameTooLarge { len: body_len.max(0) as usize });
        }
        let total = 4 + body_len as usize;
        if self.buf.len() < total {
            return Ok(None);
        }
        let packet_id = i32::from_le_bytes(self.buf[4..8].try_into().unwrap());
        let payload = self.buf[8..total].to_vec();
        self.buf.drain(..total);
        Ok(Some((packet_id, payload)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip_and_chunking() {
        let payload = b"hello";
        let frame = encode_frame(364, payload);
        assert_eq!(frame.len(), 4 + 4 + 5);
        assert_eq!(i32::from_le_bytes(frame[0..4].try_into().unwrap()), 9);

        let mut dec = FrameDecoder::new();
        // Feed in awkward pieces, including a second frame glued on.
        dec.feed(&frame[..3]);
        assert!(dec.next_frame().unwrap().is_none());
        dec.feed(&frame[3..]);
        dec.feed(&encode_frame(0, &[]));
        let (id, body) = dec.next_frame().unwrap().unwrap();
        assert_eq!(id, 364);
        assert_eq!(body, payload);
        let (id, body) = dec.next_frame().unwrap().unwrap();
        assert_eq!(id, 0);
        assert!(body.is_empty());
        assert!(dec.next_frame().unwrap().is_none());
    }

    #[test]
    fn frame_rejects_bad_length() {
        let mut dec = FrameDecoder::new();
        dec.feed(&3i32.to_le_bytes());
        assert!(matches!(dec.next_frame(), Err(ProtoError::FrameTooLarge { .. })));
    }
}
