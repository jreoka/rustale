//! Stream framing, as in the reference PacketIO.writeFramedPacket: each
//! frame on a QUIC stream is [i32 LE payload length][i32 LE packet id]
//! [payload]. The length counts the payload ONLY (for compressed packets,
//! the compressed payload) — verified against the reference writer, which
//! stores the serializer's returned size at the length offset.

use crate::io::{ProtoError, Result};

/// Largest accepted payload in one frame. Individual packets enforce
/// their own smaller MaxSize during deserialization.
pub const MAX_FRAME_PAYLOAD: usize = 64 * 1024 * 1024;

pub fn encode_frame(packet_id: i32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload.len());
    out.extend_from_slice(&(payload.len() as i32).to_le_bytes());
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
        let payload_len = i32::from_le_bytes(self.buf[0..4].try_into().unwrap());
        if payload_len < 0 || payload_len as usize > MAX_FRAME_PAYLOAD {
            return Err(ProtoError::FrameTooLarge { len: payload_len.max(0) as usize });
        }
        let total = 8 + payload_len as usize;
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
        // The length prefix counts the payload only (reference semantics;
        // a symmetric off-by-four here is exactly what the first real
        // client caught, so pin it).
        assert_eq!(i32::from_le_bytes(frame[0..4].try_into().unwrap()), 5);

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
        dec.feed(&(-1i32).to_le_bytes());
        assert!(matches!(dec.next_frame(), Err(ProtoError::FrameTooLarge { .. })));
        let mut dec = FrameDecoder::new();
        dec.feed(&((MAX_FRAME_PAYLOAD + 1) as i32).to_le_bytes());
        assert!(matches!(dec.next_frame(), Err(ProtoError::FrameTooLarge { .. })));
    }
}
