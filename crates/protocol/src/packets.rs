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
    pub const AUTH_GRANT: i32 = 11;
    pub const AUTH_TOKEN: i32 = 12;
    pub const SERVER_AUTH_TOKEN: i32 = 13;
    pub const CONNECT_ACCEPT: i32 = 14;
    pub const WORLD_SETTINGS: i32 = 20;
    pub const WORLD_LOAD_PROGRESS: i32 = 21;
    pub const WORLD_LOAD_FINISHED: i32 = 22;
    pub const REQUEST_ASSETS: i32 = 23;
    pub const ASSET_INITIALIZE: i32 = 24;
    pub const ASSET_PART: i32 = 25;
    pub const ASSET_FINALIZE: i32 = 26;
    pub const SET_UPDATE_RATE: i32 = 29;
    pub const SET_TIME_DILATION: i32 = 30;
    pub const UPDATE_FEATURES: i32 = 31;
    pub const VIEW_RADIUS: i32 = 32;
    pub const SETUP_FINALIZE: i32 = 33;
    pub const SET_CLIENT_ID: i32 = 100;
    pub const JOIN_WORLD: i32 = 104;
    pub const CLIENT_READY: i32 = 105;
    pub const SET_CHUNK: i32 = 131;
    pub const SET_CHUNK_HEIGHTMAP: i32 = 132;
    pub const SET_COLUMN: i32 = 138;
    pub const SET_CHUNK_ENVIRONMENTS: i32 = 134;
    pub const CLEAR_CHUNKS: i32 = 139;
    pub const SET_ENTITY_SEED: i32 = 160;
    pub const ENTITY_UPDATES: i32 = 161;
    pub const VOICE_CONFIG: i32 = 452;
    pub const UPDATE_WORLD_MAP_SETTINGS: i32 = 240;
    pub const WORLD_GAMEPLAY_CONFIG: i32 = 185;
    pub const UPDATE_SUN_SETTINGS: i32 = 360;
    pub const UPDATE_POST_FX_SETTINGS: i32 = 361;
    pub const SERVER_INFO: i32 = 223;
    pub const ADD_TO_SERVER_PLAYER_LIST: i32 = 224;
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

/// Best-effort structural diagnosis of a Connect payload that failed to
/// parse: dumps the fixed header fields and the offset slots, which is
/// enough to spot a protocol-build layout difference (e.g. an extra
/// variable field shifting the variable block by one slot).
pub fn diagnose_connect(buf: &[u8]) -> String {
    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ")
    }
    if buf.len() < 46 {
        return format!("payload too short for fixed block: {} bytes; head: {}", buf.len(), hex(&buf[..buf.len().min(32)]));
    }
    let r = Reader::new(buf);
    let null_bits = r.u8_at(0).unwrap_or(0);
    let crc = r.u32_at(1).unwrap_or(0);
    let build = r.i32_at(5).unwrap_or(0);
    let version = r.fixed_string_at(9, 20, true).unwrap_or_else(|_| "<invalid>".into());
    let client_type = r.u8_at(29).unwrap_or(0);
    let slots: Vec<i32> = (0..5).map(|i| r.i32_at(30 + 4 * i).unwrap_or(0)).collect();
    format!(
        "len={} nullbits={null_bits:08b} crc={crc} (ours {PROTOCOL_CRC}) build={build} (ours {PROTOCOL_BUILD_NUMBER}) \
         version={version:?} client_type={client_type} slots[30..50]={slots:?} head={}",
        buf.len(),
        hex(&buf[..64.min(buf.len())])
    )
}

/// Serialize a packet with two nullable string fields (nullbits byte,
/// two offset slots, fields in declaration order).
fn ser_two_strings(a: &Option<String>, a_max: usize, b: &Option<String>, b_max: usize) -> Result<Vec<u8>> {
    let mut w = Writer::new();
    let mut null_bits = 0u8;
    if a.is_some() {
        null_bits |= 0x01;
    }
    if b.is_some() {
        null_bits |= 0x02;
    }
    w.write_u8(null_bits);
    let slot_a = w.reserve_offset();
    let slot_b = w.reserve_offset();
    let var_start = w.position();
    debug_assert_eq!(var_start, 9);
    match a {
        Some(s) => {
            w.write_offset_at(slot_a, (w.position() - var_start) as i32);
            w.write_string(s, a_max)?;
        }
        None => w.write_offset_at(slot_a, -1),
    }
    match b {
        Some(s) => {
            w.write_offset_at(slot_b, (w.position() - var_start) as i32);
            w.write_string(s, b_max)?;
        }
        None => w.write_offset_at(slot_b, -1),
    }
    Ok(w.buf)
}

/// Read a two-nullable-variable-field packet, walking the fields in
/// declaration order and requiring each slot to match the walk position.
fn read_two<T, U>(
    buf: &[u8],
    read_a: impl Fn(&Reader, usize) -> Result<(T, usize)>,
    read_b: impl Fn(&Reader, usize) -> Result<(U, usize)>,
) -> Result<(Option<T>, Option<U>)> {
    const VAR_START: usize = 9;
    if buf.len() < VAR_START {
        return Err(ProtoError::BufferTooSmall { needed: VAR_START, have: buf.len() });
    }
    let r = Reader::new(buf);
    let null_bits = r.u8_at(0)?;
    let mut pos = VAR_START;
    let a = match (null_bits & 0x01 != 0, r.var_offset(1, VAR_START)?) {
        (true, Some(p)) => {
            if p != pos {
                return Err(ProtoError::NonCanonicalLayout { field: "auth field A" });
            }
            let (v, next) = read_a(&r, p)?;
            pos = next;
            Some(v)
        }
        (false, None) => None,
        _ => return Err(ProtoError::NonCanonicalLayout { field: "auth field A (bit/slot)" }),
    };
    let b = match (null_bits & 0x02 != 0, r.var_offset(5, VAR_START)?) {
        (true, Some(p)) => {
            if p != pos {
                return Err(ProtoError::NonCanonicalLayout { field: "auth field B" });
            }
            Some(read_b(&r, p)?.0)
        }
        (false, None) => None,
        _ => return Err(ProtoError::NonCanonicalLayout { field: "auth field B (bit/slot)" }),
    };
    Ok((a, b))
}

/// Packet 11, server -> client. Carries the session-service authorization
/// grant for the client's identity token, plus the server's own identity
/// token so the client can authenticate the server back.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthGrant {
    pub authorization_grant: Option<String>,
    pub server_identity_token: Option<String>,
}

impl AuthGrant {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        ser_two_strings(&self.authorization_grant, 4096, &self.server_identity_token, 8192)
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self> {
        let (authorization_grant, server_identity_token) =
            read_two(buf, |r, p| r.string_at(p, 4096, false), |r, p| r.string_at(p, 8192, false))?;
        Ok(AuthGrant { authorization_grant, server_identity_token })
    }
}

/// Packet 12, client -> server. The client's access token (a JWT minted
/// for this server's audience) plus an authorization grant for the server.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthToken {
    pub access_token: Option<String>,
    pub server_authorization_grant: Option<String>,
}

impl AuthToken {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        ser_two_strings(&self.access_token, 8192, &self.server_authorization_grant, 4096)
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self> {
        let (access_token, server_authorization_grant) =
            read_two(buf, |r, p| r.string_at(p, 8192, false), |r, p| r.string_at(p, 4096, false))?;
        Ok(AuthToken { access_token, server_authorization_grant })
    }
}

/// Packet 13, server -> client. The server's access token (proof the
/// server exchanged the client's grant), plus a password challenge when
/// the server has a password (we never set one).
#[derive(Debug, Clone, PartialEq)]
pub struct ServerAuthToken {
    pub server_access_token: Option<String>,
    pub password_challenge: Option<Vec<u8>>,
}

impl ServerAuthToken {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        let mut null_bits = 0u8;
        if self.server_access_token.is_some() {
            null_bits |= 0x01;
        }
        if self.password_challenge.is_some() {
            null_bits |= 0x02;
        }
        w.write_u8(null_bits);
        let slot_a = w.reserve_offset();
        let slot_b = w.reserve_offset();
        let var_start = w.position();
        debug_assert_eq!(var_start, 9);
        match &self.server_access_token {
            Some(s) => {
                w.write_offset_at(slot_a, (w.position() - var_start) as i32);
                w.write_string(s, 8192)?;
            }
            None => w.write_offset_at(slot_a, -1),
        }
        match &self.password_challenge {
            Some(b) => {
                w.write_offset_at(slot_b, (w.position() - var_start) as i32);
                w.write_byte_array(b, 64)?;
            }
            None => w.write_offset_at(slot_b, -1),
        }
        Ok(w.buf)
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self> {
        let (server_access_token, password_challenge) =
            read_two(buf, |r, p| r.string_at(p, 8192, false), |r, p| r.byte_array_at(p, 64))?;
        Ok(ServerAuthToken { server_access_token, password_challenge })
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
    fn real_client_connect_frame() {
        // Regression for the first real-client test: a Connect carrying a
        // 1728-byte identity token and language "en-US" is exactly 1782
        // payload bytes, and its frame length prefix counts those 1782
        // bytes only. (Our original framing counted id+payload and cut
        // every real packet four bytes short.)
        let mut token = String::from("eyJ");
        while token.len() < 1728 {
            token.push('x');
        }
        let connect = Connect {
            protocol_crc: PROTOCOL_CRC,
            protocol_build_number: PROTOCOL_BUILD_NUMBER,
            client_version: "0.7.4".to_string(),
            client_type: 0,
            identity_token: Some(token),
            language: "en-US".to_string(),
            referral_data: None,
            referral_source: None,
        };
        let payload = connect.serialize().unwrap();
        assert_eq!(payload.len(), 1782);
        let frame = crate::frame::encode_frame(ids::CONNECT, &payload);
        assert_eq!(i32::from_le_bytes(frame[0..4].try_into().unwrap()), 1782);
        let mut dec = crate::frame::FrameDecoder::new();
        dec.feed(&frame);
        let (id, raw) = dec.next_frame().unwrap().unwrap();
        assert_eq!(id, ids::CONNECT);
        assert_eq!(raw.len(), 1782);
        let parsed = Connect::deserialize(&raw).unwrap();
        assert_eq!(parsed.language, "en-US");
        assert_eq!(parsed.identity_token.unwrap().len(), 1728);
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

#[cfg(test)]
mod auth_packet_tests {
    use super::*;

    #[test]
    fn auth_packets_round_trip() {
        let g = AuthGrant {
            authorization_grant: Some("grant-abc".into()),
            server_identity_token: Some("identity-jwt".into()),
        };
        assert_eq!(AuthGrant::deserialize(&g.serialize().unwrap()).unwrap(), g);
        let g2 = AuthGrant { authorization_grant: None, server_identity_token: Some("x".into()) };
        assert_eq!(AuthGrant::deserialize(&g2.serialize().unwrap()).unwrap(), g2);

        let t = AuthToken {
            access_token: Some("access-jwt".into()),
            server_authorization_grant: None,
        };
        assert_eq!(AuthToken::deserialize(&t.serialize().unwrap()).unwrap(), t);

        let s = ServerAuthToken {
            server_access_token: Some("server-access".into()),
            password_challenge: Some(vec![7u8; 32]),
        };
        let bytes = s.serialize().unwrap();
        // nullbits(1) + slots(8) + varint+13 + varint+32
        assert_eq!(bytes.len(), 9 + 14 + 33);
        assert_eq!(ServerAuthToken::deserialize(&bytes).unwrap(), s);
        let s2 = ServerAuthToken { server_access_token: None, password_challenge: None };
        assert_eq!(ServerAuthToken::deserialize(&s2.serialize().unwrap()).unwrap(), s2);
    }
}
