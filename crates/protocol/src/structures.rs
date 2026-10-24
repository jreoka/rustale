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
        // null), then markup_enabled.
        for b in [self.bold, self.italic, self.monospace, self.underlined, self.strikethrough] {
            w.write_u8(b.unwrap_or(false) as u8);
        }
        w.write_u8(self.markup_enabled as u8);

        // Offset slots for the 8 variable fields, in declaration order.
        let raw_slot = w.reserve_offset();
        let id_slot = w.reserve_offset();
        let children_slot = w.reserve_offset();
        let params_slot = w.reserve_offset();
        let msg_params_slot = w.reserve_offset();
        let color_slot = w.reserve_offset();
        let link_slot = w.reserve_offset();
        let image_slot = w.reserve_offset();
        let var_start = w.position();
        debug_assert_eq!(var_start, 40);
        for slot in [params_slot, msg_params_slot, image_slot] {
            w.write_offset_at(slot, -1);
        }

        let write_opt_string = |w: &mut Writer, slot: usize, value: &Option<String>, max: usize| -> Result<()> {
            match value {
                Some(s) => {
                    w.write_offset_at(slot, (w.position() - var_start) as i32);
                    w.write_string(s, max)
                }
                None => {
                    w.write_offset_at(slot, -1);
                    Ok(())
                }
            }
        };
        write_opt_string(&mut w, raw_slot, &self.raw_text, 1_000_000)?;
        write_opt_string(&mut w, id_slot, &self.message_id, 1_000_000)?;
        match &self.children {
            Some(children) => {
                w.write_offset_at(children_slot, (w.position() - var_start) as i32);
                w.write_var_int(children.len() as u32);
                for child in children {
                    let bytes = child.serialize()?;
                    w.buf.extend_from_slice(&bytes);
                }
            }
            None => w.write_offset_at(children_slot, -1),
        }
        write_opt_string(&mut w, color_slot, &self.color, 64)?;
        write_opt_string(&mut w, link_slot, &self.link, 4096)?;
        Ok(w.buf)
    }

    /// Extract the identifying fields; other slots are skipped via their
    /// offsets. Used for logging disconnect reasons.
    pub fn deserialize_shallow(buf: &[u8]) -> Result<Self> {
        if buf.len() < 40 {
            return Err(ProtoError::BufferTooSmall { needed: 40, have: buf.len() });
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
        // Slots: raw_text @8, message_id @12, children @16, params @20,
        // message_params @24, color @28, link @32, image @36; var start 40.
        if has(0) {
            if let Some(p) = r.var_offset(8, 40)? {
                msg.raw_text = Some(r.string_at(p, 1_000_000, false)?.0);
            }
        }
        if has(1) {
            if let Some(p) = r.var_offset(12, 40)? {
                msg.message_id = Some(r.string_at(p, 1_000_000, false)?.0);
            }
        }
        if has(5) {
            if let Some(p) = r.var_offset(28, 40)? {
                msg.color = Some(r.string_at(p, 64, false)?.0);
            }
        }
        if has(11) {
            if let Some(p) = r.var_offset(32, 40)? {
                msg.link = Some(r.string_at(p, 4096, false)?.0);
            }
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
        // 40-byte header (2 null-bits + 5 bool bytes + markup + 8 slots),
        // then varint length + the key.
        assert_eq!(bytes.len(), 40 + 1 + 37);
        assert_eq!(bytes[0], 0b0000_0010); // only message_id present
        assert_eq!(bytes[1], 0);
        let parsed = FormattedMessage::deserialize_shallow(&bytes).unwrap();
        assert_eq!(parsed.message_id.as_deref(), Some("client.general.worldLoad.loadingWorld"));
    }
}
