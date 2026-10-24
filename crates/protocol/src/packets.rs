//! Packet definitions transcribed from the shared-source protocol
//! definitions (release patchline, protocol build 258). Layouts mirror the
//! generated reference serializers exactly: null-bits byte, fixed block,
//! one i32 offset slot per variable field, variable block.

use crate::io::{ProtoError, Reader, Result, Writer};

/// Protocol CRC of the release build this implementation targets.
pub const PROTOCOL_CRC: u32 = 3_908_406_161;
/// Protocol build number of the release build this targets.
pub const PROTOCOL_BUILD_NUMBER: i32 = 258;
/// QUIC ALPN for this protocol version.
pub const ALPN: &[u8] = b"hytale/3";

pub mod ids {
    pub const CONNECT: i32 = 0;
    pub const CLIENT_DISCONNECT: i32 = 1;
    pub const SERVER_DISCONNECT: i32 = 2;
    pub const PING: i32 = 3;
    pub const PONG: i32 = 4;
    pub const NETWORK_TICK: i32 = 5;
    pub const CONNECT_ACCEPT: i32 = 14;
    pub const WORLD_SETTINGS: i32 = 20;
    pub const WORLD_LOAD_PROGRESS: i32 = 21;
    pub const WORLD_LOAD_FINISHED: i32 = 22;
    pub const REQUEST_ASSETS: i32 = 23;
    pub const ASSET_INITIALIZE: i32 = 24;
    pub const ASSET_PART: i32 = 25;
    pub const ASSET_FINALIZE: i32 = 26;
    pub const SET_UPDATE_RATE: i32 = 29;
    pub const VIEW_RADIUS: i32 = 32;
    pub const SETUP_FINALIZE: i32 = 33;
    pub const SERVER_INFO: i32 = 223;
    pub const INSECURE_PLAYER_OPTIONS: i32 = 363;
    pub const REQUEST_INSECURE_PLAYER_OPTIONS: i32 = 364;
}

/// Whether the packet's payload travels zstd-compressed inside its frame.
/// Extracted from the generated reference serializers (84 packet types,
/// including all the Update* registry packets and the chunk packets).
pub fn is_compressed(packet_id: i32) -> bool {
    matches!(
        packet_id,
        20 | 23 | 25 | 40..=68 | 72..=94 | 131..=134 | 136 | 138 | 161 | 170 | 181 | 182 | 200
            | 201 | 217 | 218 | 222 | 235 | 238 | 241 | 253 | 262 | 305 | 313 | 319 | 320 | 323
            | 344 | 411 | 429 | 508
    )
}

/// Upper bound accepted for a decompressed packet payload.
pub const MAX_PACKET_PAYLOAD: usize = 256 * 1024 * 1024;

/// Frame a packet for the wire, compressing its payload if the packet
/// type calls for it.
pub fn encode_packet_frame(packet_id: i32, payload: &[u8]) -> Vec<u8> {
    if is_compressed(packet_id) && !payload.is_empty() {
        let compressed = zstd::bulk::compress(payload, 3).expect("zstd compress");
        crate::frame::encode_frame(packet_id, &compressed)
    } else {
        crate::frame::encode_frame(packet_id, payload)
    }
}

/// Recover a packet's payload from its raw frame body, decompressing if
/// the packet type calls for it.
pub fn decode_packet_payload(packet_id: i32, raw: &[u8]) -> Result<Vec<u8>> {
    if is_compressed(packet_id) && !raw.is_empty() {
        zstd::bulk::decompress(raw, MAX_PACKET_PAYLOAD)
            .map_err(|_| ProtoError::DecompressionFailed)
    } else {
        Ok(raw.to_vec())
    }
}

/// Packet 2, server -> client. Single variable field -> inline.
/// `disconnect_type`: 0 = Disconnect, 1 = Crash.
#[derive(Debug, Clone, PartialEq)]
pub struct ServerDisconnect {
    pub reason: Option<crate::structures::FormattedMessage>,
    pub disconnect_type: u8,
}

impl ServerDisconnect {
    pub fn new_translation(key: &str) -> Self {
        ServerDisconnect {
            reason: Some(crate::structures::FormattedMessage::translation(key)),
            disconnect_type: 0,
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.write_u8(self.reason.is_some() as u8);
        w.write_u8(self.disconnect_type);
        if let Some(reason) = &self.reason {
            w.buf.extend_from_slice(&reason.serialize()?);
        }
        Ok(w.buf)
    }
}

/// HostAddress structure: fixed block is just the port, variable fields
/// follow inline (structures have no offset slots).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAddress {
    pub host: String,
    pub port: i16,
}

impl HostAddress {
    pub fn serialize(&self, w: &mut Writer) -> Result<()> {
        w.write_i16(self.port);
        w.write_string(&self.host, 256)
    }

    pub fn deserialize(r: &Reader, pos: usize) -> Result<(Self, usize)> {
        let port = r.i16_at(pos)?;
        let (host, next) = r.string_at(pos + 2, 256, false)?;
        Ok((HostAddress { host, port }, next))
    }
}

/// Packet 0, client -> server. First packet on a connection; carries the
/// protocol compatibility check values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connect {
    pub protocol_crc: u32,
    pub protocol_build_number: i32,
    /// Fixed-length 20-byte ASCII field on the wire.
    pub client_version: String,
    /// ClientType enum: 0 = Game, 1 = Editor.
    pub client_type: u8,
    pub identity_token: Option<String>,
    pub language: String,
    pub referral_data: Option<Vec<u8>>,
    pub referral_source: Option<HostAddress>,
}

impl Connect {
    pub const FIXED_BLOCK_SIZE: usize = 30;
    pub const VAR_BLOCK_START: usize = 46;

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        let mut null_bits = 0u8;
        if self.identity_token.is_some() {
            null_bits |= 0x01;
        }
        if self.referral_data.is_some() {
            null_bits |= 0x02;
        }
        if self.referral_source.is_some() {
            null_bits |= 0x04;
        }
        w.write_u8(null_bits);
        w.write_u32(self.protocol_crc);
        w.write_i32(self.protocol_build_number);
        w.write_fixed_ascii(&self.client_version, 20)?;
        w.write_u8(self.client_type);

        let token_slot = w.reserve_offset();
        let language_slot = w.reserve_offset();
        let referral_data_slot = w.reserve_offset();
        let referral_source_slot = w.reserve_offset();
        let var_start = w.position();
        debug_assert_eq!(var_start, Self::VAR_BLOCK_START);

        match &self.identity_token {
            Some(token) => {
                w.write_offset_at(token_slot, (w.position() - var_start) as i32);
                w.write_string(token, 8192)?;
            }
            None => w.write_offset_at(token_slot, -1),
        }
        w.write_offset_at(language_slot, (w.position() - var_start) as i32);
        w.write_ascii_string(&self.language, 100)?;
        match &self.referral_data {
            Some(data) => {
                w.write_offset_at(referral_data_slot, (w.position() - var_start) as i32);
                w.write_byte_array(data, 4096)?;
            }
            None => w.write_offset_at(referral_data_slot, -1),
        }
        match &self.referral_source {
            Some(addr) => {
                w.write_offset_at(referral_source_slot, (w.position() - var_start) as i32);
                addr.serialize(&mut w)?;
            }
            None => w.write_offset_at(referral_source_slot, -1),
        }
        Ok(w.buf)
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::VAR_BLOCK_START {
            return Err(ProtoError::BufferTooSmall { needed: Self::VAR_BLOCK_START, have: buf.len() });
        }
        let r = Reader::new(buf);
        let null_bits = r.u8_at(0)?;
        let has_token = null_bits & 0x01 != 0;
        let has_referral_data = null_bits & 0x02 != 0;
        let has_referral_source = null_bits & 0x04 != 0;

        let protocol_crc = r.u32_at(1)?;
        let protocol_build_number = r.i32_at(5)?;
        let client_version = r.fixed_string_at(9, 20, true)?;
        let client_type = r.u8_at(29)?;
        if client_type >= 2 {
            return Err(ProtoError::InvalidEnumValue { field: "ClientType", value: client_type as u32 });
        }

        // Variable fields are walked in declaration order and each slot must
        // name exactly where the walk has reached (the reference readers
        // enforce the same canonical layout).
        fn walk(
            r: &Reader,
            slot_pos: usize,
            pos: usize,
            present: bool,
            field: &'static str,
        ) -> Result<Option<usize>> {
            let at = r.var_offset(slot_pos, Connect::VAR_BLOCK_START)?;
            match (present, at) {
                (true, Some(p)) if p == pos => Ok(Some(p)),
                (false, None) => Ok(None),
                _ => Err(ProtoError::NonCanonicalLayout { field }),
            }
        }
        let mut pos = Self::VAR_BLOCK_START;

        let identity_token = match walk(&r, 30, pos, has_token, "IdentityToken")? {
            Some(p) => {
                let (s, next) = r.string_at(p, 8192, false)?;
                pos = next;
                Some(s)
            }
            None => None,
        };
        let language = match walk(&r, 34, pos, true, "Language")? {
            Some(p) => {
                let (s, next) = r.string_at(p, 100, true)?;
                pos = next;
                s
            }
            None => unreachable!(),
        };
        let referral_data = match walk(&r, 38, pos, has_referral_data, "ReferralData")? {
            Some(p) => {
                let (data, next) = r.byte_array_at(p, 4096)?;
                pos = next;
                Some(data)
            }
            None => None,
        };
        let referral_source = match walk(&r, 42, pos, has_referral_source, "ReferralSource")? {
            Some(p) => {
                let (addr, next) = HostAddress::deserialize(&r, p)?;
                pos = next;
                Some(addr)
            }
            None => None,
        };
        let _ = pos;

        Ok(Connect {
            protocol_crc,
            protocol_build_number,
            client_version,
            client_type,
            identity_token,
            language,
            referral_data,
            referral_source,
        })
    }
}

/// Packet 363, client -> server. Sent only in offline/insecure auth mode,
/// in response to RequestInsecurePlayerOptions. The optional PlayerSkin
/// structure is captured raw for now (it is the final field, so its bytes
/// run to the end of the payload); full skin parsing lands with the
/// player phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InsecurePlayerOptions {
    pub uuid: [u8; 16],
    pub username: String,
    pub skin_raw: Option<Vec<u8>>,
}

impl InsecurePlayerOptions {
    pub const VAR_BLOCK_START: usize = 25;

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.write_u8(if self.skin_raw.is_some() { 0x01 } else { 0x00 });
        w.write_uuid(&self.uuid);
        let username_slot = w.reserve_offset();
        let skin_slot = w.reserve_offset();
        let var_start = w.position();
        debug_assert_eq!(var_start, Self::VAR_BLOCK_START);
        w.write_offset_at(username_slot, 0);
        w.write_ascii_string(&self.username, 16)?;
        match &self.skin_raw {
            Some(raw) => {
                w.write_offset_at(skin_slot, (w.position() - var_start) as i32);
                w.buf.extend_from_slice(raw);
            }
            None => w.write_offset_at(skin_slot, -1),
        }
        Ok(w.buf)
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::VAR_BLOCK_START {
            return Err(ProtoError::BufferTooSmall { needed: Self::VAR_BLOCK_START, have: buf.len() });
        }
        let r = Reader::new(buf);
        let has_skin = r.u8_at(0)? & 0x01 != 0;
        let uuid = r.uuid_at(1)?;
        let username_at = r
            .var_offset(17, Self::VAR_BLOCK_START)?
            .ok_or(ProtoError::NonCanonicalLayout { field: "Username" })?;
        let (username, after_name) = r.string_at(username_at, 16, true)?;
        let skin_raw = if has_skin {
            let skin_at = r
                .var_offset(21, Self::VAR_BLOCK_START)?
                .ok_or(ProtoError::NonCanonicalLayout { field: "Skin" })?;
            if skin_at < after_name {
                return Err(ProtoError::NonCanonicalLayout { field: "Skin" });
            }
            Some(buf[skin_at..].to_vec())
        } else {
            None
        };
        Ok(InsecurePlayerOptions { uuid, username, skin_raw })
    }
}

/// Packet 364, server -> client. Empty payload; asks an offline-mode
/// client to identify itself with InsecurePlayerOptions.
pub struct RequestInsecurePlayerOptions;

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-exact reference vector for a minimal Connect, computed from the
    /// generated reference serializer's layout (protocol build 258 values).
    const CONNECT_VECTOR: &[u8] = &[
        0x00, 0x91, 0x8b, 0xf5, 0xe8, 0x02, 0x01, 0x00, 0x00, 0x31, 0x2e, 0x30, 0x2e, 0x30, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x05, 0x65, 0x6e, 0x2d, 0x55, 0x53,
    ];

    fn sample_connect() -> Connect {
        Connect {
            protocol_crc: PROTOCOL_CRC,
            protocol_build_number: PROTOCOL_BUILD_NUMBER,
            client_version: "1.0.0".to_string(),
            client_type: 0,
            identity_token: None,
            language: "en-US".to_string(),
            referral_data: None,
            referral_source: None,
        }
    }

    #[test]
    fn connect_serializes_byte_exact() {
        let bytes = sample_connect().serialize().unwrap();
        assert_eq!(bytes, CONNECT_VECTOR);
    }

    #[test]
    fn connect_deserializes_reference_vector() {
        let parsed = Connect::deserialize(CONNECT_VECTOR).unwrap();
        assert_eq!(parsed, sample_connect());
    }

    #[test]
    fn connect_round_trip_full() {
        let mut c = sample_connect();
        c.identity_token = Some("token-abc".to_string());
        c.referral_data = Some(vec![1, 2, 3, 250]);
        c.referral_source = Some(HostAddress { host: "play.example.com".to_string(), port: 5520 });
        let bytes = c.serialize().unwrap();
        assert_eq!(Connect::deserialize(&bytes).unwrap(), c);
    }

    #[test]
    fn connect_rejects_bad_enum_and_short_buffer() {
        let mut bad = CONNECT_VECTOR.to_vec();
        bad[29] = 7;
        assert!(matches!(
            Connect::deserialize(&bad),
            Err(ProtoError::InvalidEnumValue { field: "ClientType", .. })
        ));
        assert!(Connect::deserialize(&CONNECT_VECTOR[..20]).is_err());
    }

    #[test]
    fn compressed_packet_frame_round_trip() {
        // WorldSettings (20) is a zstd packet: the framed payload must not
        // be the raw payload, and must decode back to it.
        let payload = vec![0x00u8; 512];
        let frame = encode_packet_frame(ids::WORLD_SETTINGS, &payload);
        let mut dec = crate::frame::FrameDecoder::new();
        dec.feed(&frame);
        let (id, raw) = dec.next_frame().unwrap().unwrap();
        assert_eq!(id, ids::WORLD_SETTINGS);
        assert_ne!(raw, payload);
        assert_eq!(decode_packet_payload(id, &raw).unwrap(), payload);
        // An uncompressed packet passes through untouched.
        assert!(!is_compressed(ids::CONNECT));
        assert!(is_compressed(ids::WORLD_SETTINGS));
    }

    #[test]
    fn insecure_options_round_trip() {
        let opts = InsecurePlayerOptions {
            uuid: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
                   0xEE, 0xFF, 0x00],
            username: "Cross".to_string(),
            skin_raw: None,
        };
        let bytes = opts.serialize().unwrap();
        assert_eq!(bytes.len(), 25 + 1 + 5);
        assert_eq!(InsecurePlayerOptions::deserialize(&bytes).unwrap(), opts);
    }
}
