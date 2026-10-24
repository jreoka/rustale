//! Byte-level primitives mirroring the reference protocol's PacketWriter /
//! PacketReader: little-endian fixed fields, canonical LEB128 varints,
//! varint-length-prefixed strings, and the offset-slot indirection that
//! top-level packets use for their variable-length fields.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoError {
    BufferTooSmall { needed: usize, have: usize },
    InvalidVarInt,
    NonCanonicalVarInt,
    NegativeVarInt,
    StringTooLong { len: usize, max: usize },
    InvalidUtf8,
    InvalidAscii,
    InvalidOffset { slot: i32, buf_len: usize },
    NonCanonicalLayout { field: &'static str },
    InvalidEnumValue { field: &'static str, value: u32 },
    FrameTooLarge { len: usize },
    TrailingBytes { extra: usize },
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ProtoError {}

pub type Result<T> = std::result::Result<T, ProtoError>;

/// Canonical unsigned LEB128, as in the reference VarInt: at most 5 bytes,
/// the value must fit in 32 bits, and padded (non-canonical) encodings are
/// rejected on read exactly like the C# TryRead.
pub fn write_var_int(out: &mut Vec<u8>, value: u32) {
    let mut v = value;
    while v & !0x7F != 0 {
        out.push(((v & 0x7F) as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

pub fn var_int_size(value: u32) -> usize {
    match value {
        0 => 1,
        _ => (32 - value.leading_zeros() as usize + 6) / 7,
    }
}

/// Read a varint at `pos`, returning (value, new_pos). Mirrors the reference
/// validation: a terminating byte of 0 after a continuation is non-canonical,
/// and the 5th byte may only carry bits 28..=31 (value 1..=7 with terminator,
/// where a lone 0x80.. pattern is invalid).
pub fn read_var_int(buf: &[u8], pos: &mut usize) -> Result<u32> {
    let start = *pos;
    let mut value: u32 = 0;
    for i in 0..5 {
        if *pos >= buf.len() {
            return Err(ProtoError::InvalidVarInt);
        }
        let b = buf[*pos];
        *pos += 1;
        if i == 4 {
            // Only bits 28-31 survive; terminator must be 1..=7, no continuation.
            if b & 0x80 != 0 || b == 0 || b > 7 {
                return Err(if b == 0 {
                    ProtoError::NonCanonicalVarInt
                } else {
                    ProtoError::InvalidVarInt
                });
            }
            value |= (b as u32 & 0x07) << 28;
            return Ok(value);
        }
        value |= (b as u32 & 0x7F) << (7 * i);
        if b & 0x80 == 0 {
            if i > 0 && b == 0 {
                return Err(ProtoError::NonCanonicalVarInt);
            }
            let _ = start;
            return Ok(value);
        }
    }
    Err(ProtoError::InvalidVarInt)
}

/// Growable packet writer with offset-slot patching, mirroring the generated
/// serializers: fixed block first, one i32 slot per variable field, then the
/// variable block; slots are patched with offsets relative to the variable
/// block start (or -1 for absent fields).
pub struct Writer {
    pub buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Writer { buf: Vec::new() }
    }

    pub fn position(&self) -> usize {
        self.buf.len()
    }

    pub fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn write_i16(&mut self, v: i16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_i32(&mut self, v: i32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_i64(&mut self, v: i64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_f32(&mut self, v: f32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_f64(&mut self, v: f64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_var_int(&mut self, v: u32) {
        write_var_int(&mut self.buf, v);
    }

    /// UUIDs go on the wire in canonical text order (the reference writers
    /// byte-swap out of .NET's mixed-endian in-memory layout to reach the
    /// same bytes), so a plain 16-byte copy is correct.
    pub fn write_uuid(&mut self, uuid: &[u8; 16]) {
        self.buf.extend_from_slice(uuid);
    }

    /// Fixed-length ASCII field, NUL padded to `len`.
    pub fn write_fixed_ascii(&mut self, s: &str, len: usize) -> Result<()> {
        if s.len() > len || !s.is_ascii() {
            return Err(ProtoError::StringTooLong { len: s.len(), max: len });
        }
        self.buf.extend_from_slice(s.as_bytes());
        self.buf.resize(self.buf.len() + (len - s.len()), 0);
        Ok(())
    }

    /// Varint byte-length prefix + UTF-8 bytes.
    pub fn write_string(&mut self, s: &str, max: usize) -> Result<()> {
        if s.len() > max {
            return Err(ProtoError::StringTooLong { len: s.len(), max });
        }
        self.write_var_int(s.len() as u32);
        self.buf.extend_from_slice(s.as_bytes());
        Ok(())
    }

    /// Same wire form as write_string; validates ASCII like the reference.
    pub fn write_ascii_string(&mut self, s: &str, max: usize) -> Result<()> {
        if !s.is_ascii() {
            return Err(ProtoError::InvalidAscii);
        }
        self.write_string(s, max)
    }

    pub fn write_byte_array(&mut self, data: &[u8], max: usize) -> Result<()> {
        if data.len() > max {
            return Err(ProtoError::StringTooLong { len: data.len(), max });
        }
        self.write_var_int(data.len() as u32);
        self.buf.extend_from_slice(data);
        Ok(())
    }

    /// Reserve a 4-byte offset slot; returns its position for later patching.
    pub fn reserve_offset(&mut self) -> usize {
        let pos = self.buf.len();
        self.buf.extend_from_slice(&[0; 4]);
        pos
    }

    pub fn write_offset_at(&mut self, slot: usize, offset: i32) {
        self.buf[slot..slot + 4].copy_from_slice(&offset.to_le_bytes());
    }
}

impl Default for Writer {
    fn default() -> Self {
        Self::new()
    }
}

/// Absolute-offset reader over a packet payload, mirroring the generated
/// readers: fixed fields are read by offset, variable fields through their
/// offset slots relative to the variable block start.
pub struct Reader<'a> {
    pub buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf }
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn u8_at(&self, off: usize) -> Result<u8> {
        self.buf
            .get(off)
            .copied()
            .ok_or(ProtoError::BufferTooSmall { needed: off + 1, have: self.buf.len() })
    }

    pub fn i16_at(&self, off: usize) -> Result<i16> {
        let b = self.slice(off, 2)?;
        Ok(i16::from_le_bytes([b[0], b[1]]))
    }

    pub fn i32_at(&self, off: usize) -> Result<i32> {
        let b = self.slice(off, 4)?;
        Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u32_at(&self, off: usize) -> Result<u32> {
        let b = self.slice(off, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn uuid_at(&self, off: usize) -> Result<[u8; 16]> {
        let b = self.slice(off, 16)?;
        let mut out = [0u8; 16];
        out.copy_from_slice(b);
        Ok(out)
    }

    pub fn slice(&self, off: usize, len: usize) -> Result<&'a [u8]> {
        if off + len > self.buf.len() {
            return Err(ProtoError::BufferTooSmall { needed: off + len, have: self.buf.len() });
        }
        Ok(&self.buf[off..off + len])
    }

    /// Fixed-length, NUL-terminated string field at `off`.
    pub fn fixed_string_at(&self, off: usize, len: usize, ascii: bool) -> Result<String> {
        let raw = self.slice(off, len)?;
        let end = raw.iter().position(|&c| c == 0).unwrap_or(len);
        let s = &raw[..end];
        if ascii && !s.is_ascii() {
            return Err(ProtoError::InvalidAscii);
        }
        String::from_utf8(s.to_vec()).map_err(|_| ProtoError::InvalidUtf8)
    }

    /// Resolve an offset slot (at `slot_pos`) to an absolute position.
    /// Absent fields carry -1; returns Ok(None) for those.
    pub fn var_offset(&self, slot_pos: usize, var_block_start: usize) -> Result<Option<usize>> {
        let slot = self.i32_at(slot_pos)?;
        if slot == -1 {
            return Ok(None);
        }
        if slot < 0 || var_block_start + slot as usize > self.buf.len() {
            return Err(ProtoError::InvalidOffset { slot, buf_len: self.buf.len() });
        }
        Ok(Some(var_block_start + slot as usize))
    }

    /// Read a varint-length-prefixed string at absolute `pos`.
    /// Returns (string, new_pos).
    pub fn string_at(&self, mut pos: usize, max: usize, ascii: bool) -> Result<(String, usize)> {
        let len = read_var_int(self.buf, &mut pos)? as usize;
        if len > max {
            return Err(ProtoError::StringTooLong { len, max });
        }
        let raw = self.slice(pos, len)?;
        if ascii && !raw.is_ascii() {
            return Err(ProtoError::InvalidAscii);
        }
        let s = String::from_utf8(raw.to_vec()).map_err(|_| ProtoError::InvalidUtf8)?;
        Ok((s, pos + len))
    }

    /// Read a varint-length-prefixed byte array at absolute `pos`.
    pub fn byte_array_at(&self, mut pos: usize, max: usize) -> Result<(Vec<u8>, usize)> {
        let len = read_var_int(self.buf, &mut pos)? as usize;
        if len > max {
            return Err(ProtoError::StringTooLong { len, max });
        }
        Ok((self.slice(pos, len)?.to_vec(), pos + len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_vectors() {
        let cases: &[(u32, &[u8])] = &[
            (0, &[0x00]),
            (1, &[0x01]),
            (127, &[0x7F]),
            (128, &[0x80, 0x01]),
            (300, &[0xAC, 0x02]),
            (16_384, &[0x80, 0x80, 0x01]),
            // The reference VarInt encodes non-negative i32 values, so the
            // largest encodable value is i32::MAX (5th byte tops out at 7).
            (i32::MAX as u32, &[0xFF, 0xFF, 0xFF, 0xFF, 0x07]),
        ];
        for (value, bytes) in cases {
            let mut out = Vec::new();
            write_var_int(&mut out, *value);
            assert_eq!(&out, bytes, "encode {value}");
            let mut pos = 0;
            assert_eq!(read_var_int(bytes, &mut pos).unwrap(), *value);
            assert_eq!(pos, bytes.len());
            assert_eq!(var_int_size(*value), bytes.len());
        }
    }

    #[test]
    fn varint_rejects_noncanonical_and_overflow() {
        // Padded encoding of 0.
        let mut pos = 0;
        assert_eq!(read_var_int(&[0x80, 0x00], &mut pos), Err(ProtoError::NonCanonicalVarInt));
        // 5th byte above 7 would overflow 32 bits.
        let mut pos = 0;
        assert_eq!(
            read_var_int(&[0xFF, 0xFF, 0xFF, 0xFF, 0x08], &mut pos),
            Err(ProtoError::InvalidVarInt)
        );
        // Truncated.
        let mut pos = 0;
        assert_eq!(read_var_int(&[0x80], &mut pos), Err(ProtoError::InvalidVarInt));
    }
}
