//! Shared protocol structures (the `[ProtocolStruct]` types). Structures
//! serialize as: fixed block (null-bits, then fixed fields with bools
//! bit-packed), offset slots if they have 2+ variable fields, then the
//! variable block. A structure with a single variable field writes it
//! inline with no slot — same rule as packets.

use crate::io::{ProtoError, Reader, Result, Writer};

/// A named common-asset file with its content hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asset {
    /// Fixed-length 64-byte ASCII field on the wire.
    pub hash: String,
    pub name: String,
}

impl Asset {
    pub fn serialize(&self, w: &mut Writer) -> Result<()> {
        w.write_fixed_ascii(&self.hash, 64)?;
        w.write_string(&self.name, 512)
    }

    pub fn deserialize(r: &Reader, pos: usize) -> Result<(Self, usize)> {
        let hash = r.fixed_string_at(pos, 64, true)?;
        let (name, next) = r.string_at(pos + 64, 512, false)?;
        Ok((Asset { hash, name }, next))
    }
}

/// The rich-text message type used for disconnect reasons, world-load
/// status, chat, and more. Only the fields we need are modelled; unknown
/// params are not encoded (decoding extracts the id/raw text and ignores
/// the rest via the offset slots, like the reference random-access
/// readers do).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct FormattedMessage {
    pub raw_text: Option<String>,
    pub message_id: Option<String>,
    pub children: Option<Vec<FormattedMessage>>,
    pub color: Option<String>,
    pub bold: Option<bool>,
    pub italic: Option<bool>,
    pub monospace: Option<bool>,
    pub underlined: Option<bool>,
    pub strikethrough: Option<bool>,
    pub link: Option<String>,
    pub markup_enabled: bool,
}

impl FormattedMessage {
    /// A translation-key message, as produced by Message.translation().
    pub fn translation(key: &str) -> Self {
        FormattedMessage { message_id: Some(key.to_string()), ..Default::default() }
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        // Nullable fields in declaration order (13 bits over 2 bytes):
        // raw_text, message_id, children, params, message_params, color,
        // bold, italic, monospace, underlined, strikethrough, link, image.
        let present = [
            self.raw_text.is_some(),
            self.message_id.is_some(),
            self.children.is_some(),
            false, // params: not modelled
            false, // message_params: not modelled
            self.color.is_some(),
            self.bold.is_some(),
            self.italic.is_some(),
            self.monospace.is_some(),
            self.underlined.is_some(),
            self.strikethrough.is_some(),
            self.link.is_some(),
            false, // image: not modelled
        ];
        let mut null_bits = [0u8; 2];
        for (i, p) in present.iter().enumerate() {
            if *p {
                null_bits[i / 8] |= 1 << (i % 8);
            }
        }
        w.buf.extend_from_slice(&null_bits);
        // Fixed block: the five nullable bools (byte reserved even when
        // null), then markup_enabled. Total fixed block = 8 bytes,
        // matching the generated FormattedMessage constants.
        for b in [self.bold, self.italic, self.monospace, self.underlined, self.strikethrough] {
            w.write_u8(b.unwrap_or(false) as u8);
        }
        w.write_u8(self.markup_enabled as u8);

        // Structures have NO offset slots (that is the packet layout):
        // present variable fields are written inline in declaration
        // order — raw_text, message_id, children, [params],
        // [message_params], color, link, [image]. Bracketed fields are
        // not modelled and never present in messages we produce.
        if let Some(s) = &self.raw_text {
            w.write_string(s, 1_000_000)?;
        }
        if let Some(s) = &self.message_id {
            w.write_string(s, 1_000_000)?;
        }
        if let Some(children) = &self.children {
            w.write_var_int(children.len() as u32);
            for child in children {
                let bytes = child.serialize()?;
                w.buf.extend_from_slice(&bytes);
            }
        }
        if let Some(s) = &self.color {
            w.write_string(s, 64)?;
        }
        if let Some(s) = &self.link {
            w.write_string(s, 4096)?;
        }
        Ok(w.buf)
    }

    /// Extract the identifying fields (raw_text / message_id, which lead
    /// the inline variable block). Used for logging disconnect reasons.
    /// Stops before children/params, which we don't model.
    pub fn deserialize_shallow(buf: &[u8]) -> Result<Self> {
        if buf.len() < 8 {
            return Err(ProtoError::BufferTooSmall { needed: 8, have: buf.len() });
        }
        let r = Reader::new(buf);
        let bits = [r.u8_at(0)?, r.u8_at(1)?];
        let has = |i: usize| bits[i / 8] >> (i % 8) & 1 == 1;
        let opt_bool = |present: bool, off: usize| -> Result<Option<bool>> {
            if present {
                Ok(Some(r.u8_at(off)? != 0))
            } else {
                Ok(None)
            }
        };
        let mut msg = FormattedMessage {
            bold: opt_bool(has(6), 2)?,
            italic: opt_bool(has(7), 3)?,
            monospace: opt_bool(has(8), 4)?,
            underlined: opt_bool(has(9), 5)?,
            strikethrough: opt_bool(has(10), 6)?,
            markup_enabled: r.u8_at(7)? != 0,
            ..Default::default()
        };
        // Variable fields are inline from offset 8, in declaration order.
        let mut pos = 8;
        if has(0) {
            let (s, next) = r.string_at(pos, 1_000_000, false)?;
            msg.raw_text = Some(s);
            pos = next;
        }
        if has(1) {
            let (s, _) = r.string_at(pos, 1_000_000, false)?;
            msg.message_id = Some(s);
        }
        Ok(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_round_trip() {
        let asset = Asset { hash: "a".repeat(64), name: "Common/Items".to_string() };
        let mut w = Writer::new();
        asset.serialize(&mut w).unwrap();
        assert_eq!(w.buf.len(), 64 + 1 + 12);
        let r = Reader::new(&w.buf);
        let (parsed, next) = Asset::deserialize(&r, 0).unwrap();
        assert_eq!(parsed, asset);
        assert_eq!(next, w.buf.len());
    }

    #[test]
    fn formatted_translation_message_layout() {
        let msg = FormattedMessage::translation("client.general.worldLoad.loadingWorld");
        let bytes = msg.serialize().unwrap();
        // 8-byte fixed block (2 null-bits + 5 bool bytes + markup byte),
        // then the inline varint length + the key. Structures use no
        // offset slots.
        assert_eq!(bytes.len(), 8 + 1 + 37);
        assert_eq!(bytes[0], 0b0000_0010); // only message_id present
        assert_eq!(bytes[1], 0);
        let parsed = FormattedMessage::deserialize_shallow(&bytes).unwrap();
        assert_eq!(parsed.message_id.as_deref(), Some("client.general.worldLoad.loadingWorld"));
    }
}

#[cfg(test)]
mod formatted_message_tests {
    use super::*;

    #[test]
    fn translation_message_layout() {
        // Structure layout: NO offset slots. nullbits(2) + 5 bool bytes +
        // markup byte = 8 fixed, then the message_id string inline.
        let msg = FormattedMessage::translation("client.general.worldLoad.loadingWorld");
        let bytes = msg.serialize().unwrap();
        assert_eq!(bytes.len(), 8 + 1 + 37);
        assert_eq!(bytes[0], 0x02); // bit 1: message_id present
        assert_eq!(bytes[1], 0x00);
        assert!(bytes[2..8].iter().all(|b| *b == 0));
        assert_eq!(bytes[8], 37);
        assert_eq!(&bytes[9..], b"client.general.worldLoad.loadingWorld");
        let back = FormattedMessage::deserialize_shallow(&bytes).unwrap();
        assert_eq!(back.message_id.as_deref(), Some("client.general.worldLoad.loadingWorld"));
    }
}
