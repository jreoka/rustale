//! World-entry packets: the join burst the reference server sends from
//! World.onFinishPlayerJoining, and the chunk packets. Chunk geometry:
//! 32x32 columns, 10 sections of 32 blocks (world height 320).

use crate::io::{ProtoError, Result, Writer};

pub const CHUNK_SIZE: i32 = 32;
pub const HEIGHT_SECTIONS: i32 = 10;
pub const WORLD_HEIGHT: i32 = CHUNK_SIZE * HEIGHT_SECTIONS;
pub const SECTION_BLOCKS: usize = 32 * 32 * 32;

// ---------------------------------------------------------------------------
// SetClientId (100): the network id of the client's own player entity.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetClientId {
    pub client_id: i32,
}

impl SetClientId {
    pub fn serialize(&self) -> Vec<u8> {
        self.client_id.to_le_bytes().to_vec()
    }
}

// ---------------------------------------------------------------------------
// SetEntitySeed (160).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetEntitySeed {
    pub entity_seed: i32,
}

impl SetEntitySeed {
    pub fn serialize(&self) -> Vec<u8> {
        self.entity_seed.to_le_bytes().to_vec()
    }
}

// ---------------------------------------------------------------------------
// SetTimeDilation (30).

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SetTimeDilation {
    pub time_dilation: f32,
}

impl SetTimeDilation {
    pub fn serialize(&self) -> Vec<u8> {
        self.time_dilation.to_le_bytes().to_vec()
    }
}

// ---------------------------------------------------------------------------
// SetUpdateRate (29).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetUpdateRate {
    pub updates_per_second: i32,
}

impl SetUpdateRate {
    pub fn serialize(&self) -> Vec<u8> {
        self.updates_per_second.to_le_bytes().to_vec()
    }
}

// ---------------------------------------------------------------------------
// UpdateFeatures (31): Dictionary<ClientFeature, bool>. Single variable
// field -> inline. We send an empty (present) map until individual client
// features matter.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateFeatures {
    pub features: Option<Vec<(u8, bool)>>,
}

impl UpdateFeatures {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.write_u8(self.features.is_some() as u8);
        if let Some(features) = &self.features {
            w.write_var_int(features.len() as u32);
            for (feature, enabled) in features {
                w.write_u8(*feature);
                w.write_u8(*enabled as u8);
            }
        }
        Ok(w.buf)
    }
}

// ---------------------------------------------------------------------------
// UpdateSunSettings (360) / UpdatePostFxSettings (361): plain float fields.

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UpdateSunSettings {
    pub height_percentage: f32,
    pub angle_radians: f32,
}

impl UpdateSunSettings {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8);
        out.extend_from_slice(&self.height_percentage.to_le_bytes());
        out.extend_from_slice(&self.angle_radians.to_le_bytes());
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UpdatePostFxSettings {
    pub global_intensity: f32,
    pub power: f32,
    pub sunshaft_scale: f32,
    pub sun_intensity: f32,
    pub sunshaft_intensity: f32,
}

impl UpdatePostFxSettings {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(20);
        for v in [
            self.global_intensity,
            self.power,
            self.sunshaft_scale,
            self.sun_intensity,
            self.sunshaft_intensity,
        ] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out
    }
}

// ---------------------------------------------------------------------------
// JoinWorld (104). Fixed block only: null-bits for the two nullable
// section bounds, bit-packed bools, the world UUID, and the two bounds
// (fixed bytes reserved even when null).

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinWorld {
    pub clear_world: bool,
    pub fade_in_out: bool,
    pub world_uuid: [u8; 16],
    pub min_section_y: Option<i32>,
    pub max_section_y: Option<i32>,
}

impl JoinWorld {
    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        let mut null_bits = 0u8;
        if self.min_section_y.is_some() {
            null_bits |= 0x01;
        }
        if self.max_section_y.is_some() {
            null_bits |= 0x02;
        }
        w.write_u8(null_bits);
        w.write_bool_bits(&[self.clear_world, self.fade_in_out]);
        w.write_uuid(&self.world_uuid);
        w.write_i32(self.min_section_y.unwrap_or(0));
        w.write_i32(self.max_section_y.unwrap_or(0));
        w.buf
    }
}

// ---------------------------------------------------------------------------
// WorldGameplayConfig (185). Its three structure fields serialize inline
// in the generated order CombatConfig, PlayerConfig, WorldConfig (the two
// fixed-size structures form the fixed block; WorldConfig is the single
// variable field). ArmorVisibilityOption: All=0, HelmetOnly=1, None=2.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorldGameplayConfig {
    pub display_health_bars: bool,
    pub display_combat_text: bool,
    pub armor_visibility_none: bool,
    pub allow_block_breaking: bool,
    pub allow_block_gathering: bool,
    pub allow_block_placement: bool,
}

impl Default for WorldGameplayConfig {
    fn default() -> Self {
        WorldGameplayConfig {
            display_health_bars: true,
            display_combat_text: true,
            armor_visibility_none: true,
            allow_block_breaking: true,
            allow_block_gathering: true,
            allow_block_placement: true,
        }
    }
}

impl WorldGameplayConfig {
    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        // CombatConfig: two bit-packed bools.
        w.write_bool_bits(&[self.display_health_bars, self.display_combat_text]);
        // PlayerConfig: the armor visibility enum byte (None = 2).
        w.write_u8(if self.armor_visibility_none { 2 } else { 0 });
        // WorldConfig: null-bits (blocked-interactions array absent),
        // AllowBlockBreaking bit, bypass tag index, gathering+placement bits.
        w.write_u8(0);
        w.write_bool_bits(&[self.allow_block_breaking]);
        w.write_i32(0);
        w.write_bool_bits(&[self.allow_block_gathering, self.allow_block_placement]);
        w.buf
    }
}

// ---------------------------------------------------------------------------
// ClientReady (105), client -> server: two bit-packed bools, no null-bits.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientReady {
    pub ready_for_chunks: bool,
    pub ready_for_gameplay: bool,
}

impl ClientReady {
    pub fn deserialize(buf: &[u8]) -> Result<Self> {
        if buf.is_empty() {
            return Err(ProtoError::BufferTooSmall { needed: 1, have: 0 });
        }
        Ok(ClientReady {
            ready_for_chunks: buf[0] & 0x01 != 0,
            ready_for_gameplay: buf[0] & 0x02 != 0,
        })
    }
}

// ---------------------------------------------------------------------------
// SetChunk (131, zstd). Three variable fields -> offset slots.
// Data is the section blob produced by `section_data` below; a section
// that is entirely air sends Data = null.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetChunk {
    pub x: i32,
    pub y: i32,
    pub z: i32,
    pub local_light: Option<Vec<u8>>,
    pub global_light: Option<Vec<u8>>,
    pub data: Option<Vec<u8>>,
}

impl SetChunk {
    pub fn air(x: i32, y: i32, z: i32) -> Self {
        SetChunk { x, y, z, local_light: None, global_light: None, data: None }
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        let mut null_bits = 0u8;
        if self.local_light.is_some() {
            null_bits |= 0x01;
        }
        if self.global_light.is_some() {
            null_bits |= 0x02;
        }
        if self.data.is_some() {
            null_bits |= 0x04;
        }
        w.write_u8(null_bits);
        w.write_i32(self.x);
        w.write_i32(self.y);
        w.write_i32(self.z);
        let local_slot = w.reserve_offset();
        let global_slot = w.reserve_offset();
        let data_slot = w.reserve_offset();
        let var_start = w.position();
        let write_field = |w: &mut Writer, slot: usize, value: &Option<Vec<u8>>| {
            match value {
                Some(bytes) => {
                    w.write_offset_at(slot, (w.position() - var_start) as i32);
                    // Byte-array fields in packets use the validated array
                    // writer: varint length + raw bytes.
                    w.write_var_int(bytes.len() as u32);
                    w.buf.extend_from_slice(bytes);
                }
                None => w.write_offset_at(slot, -1),
            }
        };
        write_field(&mut w, local_slot, &self.local_light);
        write_field(&mut w, global_slot, &self.global_light);
        write_field(&mut w, data_slot, &self.data);
        Ok(w.buf)
    }
}

/// Build the `Data` blob for a section filled with a single block id,
/// using a Byte palette (type 2), an Empty filler palette (type 0) and an
/// Empty rotation palette (type 0). Mirrors BlockSection.serializeForPacket
/// + ByteSectionPalette.serializeForPacket:
/// [type][count i16][internal u8, external i32, count i16]...[index bytes].
pub fn uniform_section_data(block_id: i32) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 2 + 7 + SECTION_BLOCKS + 2);
    out.push(2u8); // PaletteType::Byte
    out.extend_from_slice(&1i16.to_le_bytes()); // one palette entry
    out.push(0u8); // internal id 0
    out.extend_from_slice(&block_id.to_le_bytes());
    // Per-entry block count; a full section is 32768, which wraps the
    // reference's i16 counter exactly as written here (0x8000).
    out.extend_from_slice(&(SECTION_BLOCKS as u16).to_le_bytes());
    out.resize(out.len() + SECTION_BLOCKS, 0u8); // all blocks -> internal 0
    out.push(0u8); // filler palette: Empty
    out.push(0u8); // rotation palette: Empty
    out
}

// ---------------------------------------------------------------------------
// SetChunkHeightmap (132, zstd): fixed 1024-entry i32 array.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetChunkHeightmap {
    pub x: i32,
    pub z: i32,
    pub heightmap: [i32; 1024],
}

impl SetChunkHeightmap {
    pub fn uniform(x: i32, z: i32, height: i32) -> Self {
        SetChunkHeightmap { x, z, heightmap: [height; 1024] }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_i32(self.x);
        w.write_i32(self.z);
        for h in self.heightmap {
            w.write_i32(h);
        }
        w.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::Reader;

    #[test]
    fn join_world_layout() {
        let packet = JoinWorld {
            clear_world: true,
            fade_in_out: true,
            world_uuid: [0x11; 16],
            min_section_y: Some(0),
            max_section_y: Some(HEIGHT_SECTIONS - 1),
        };
        let bytes = packet.serialize();
        assert_eq!(bytes.len(), 26);
        assert_eq!(bytes[0], 0b011); // both bounds present
        assert_eq!(bytes[1], 0b011); // both bools set
        let r = Reader::new(&bytes);
        assert_eq!(r.i32_at(18).unwrap(), 0);
        assert_eq!(r.i32_at(22).unwrap(), 9);
    }

    #[test]
    fn client_ready_bits() {
        let ready = ClientReady::deserialize(&[0b11]).unwrap();
        assert!(ready.ready_for_chunks && ready.ready_for_gameplay);
        let not = ClientReady::deserialize(&[0b01]).unwrap();
        assert!(not.ready_for_chunks && !not.ready_for_gameplay);
    }

    #[test]
    fn uniform_section_data_shape() {
        let data = uniform_section_data(1);
        assert_eq!(data.len(), 1 + 2 + 7 + SECTION_BLOCKS + 2);
        assert_eq!(data[0], 2); // Byte palette
        assert_eq!(i16::from_le_bytes(data[1..3].try_into().unwrap()), 1);
        assert_eq!(i32::from_le_bytes(data[4..8].try_into().unwrap()), 1);
        assert_eq!(data[data.len() - 2], 0); // filler Empty
        assert_eq!(data[data.len() - 1], 0); // rotation Empty
    }

    #[test]
    fn set_chunk_air_and_solid() {
        let air = SetChunk::air(3, 4, 5).serialize().unwrap();
        assert_eq!(air[0], 0); // nothing present
        assert_eq!(air.len(), 1 + 12 + 12); // nullbits + xyz + 3 slots
        let solid = SetChunk {
            data: Some(uniform_section_data(2)),
            ..SetChunk::air(0, 1, 0)
        }
        .serialize()
        .unwrap();
        assert_eq!(solid[0], 0b100); // only data present
    }
}

/// SetColumn (138, zstd, Chunks channel): creates a chunk column on the
/// client. Fixed block: x, z, then the heightmap as a fixed-length
/// 1024-entry i32 array (4104 bytes total); the tintmap is the single
/// variable field and follows inline.
pub struct SetColumn {
    pub x: i32,
    pub z: i32,
    pub heightmap: [i32; 1024],
    pub tintmap: Vec<u8>,
}

impl SetColumn {
    pub fn uniform(x: i32, z: i32, height: i32) -> Self {
        // The tintmap is an IntBytePalette serialization: i16 key count,
        // that many i32 keys, an i32 data length, then the bit field —
        // 1024 column entries at 10 bits each = 1280 bytes, which the
        // client validates exactly. One key (tint 0), all entries 0.
        let mut tintmap = Vec::with_capacity(1290);
        tintmap.extend_from_slice(&1i16.to_le_bytes());
        tintmap.extend_from_slice(&0i32.to_le_bytes());
        tintmap.extend_from_slice(&1280i32.to_le_bytes());
        tintmap.resize(tintmap.len() + 1280, 0);
        SetColumn { x, z, heightmap: [height; 1024], tintmap }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_i32(self.x);
        w.write_i32(self.z);
        for h in self.heightmap {
            w.write_i32(h);
        }
        w.write_var_int(self.tintmap.len() as u32);
        w.buf.extend_from_slice(&self.tintmap);
        w.buf
    }
}

/// SetChunkEnvironments (134, zstd, Chunks channel): the environment
/// section for one chunk section. X/Y/Z fixed, then the section blob
/// inline (single variable field). Uniform mode blob = [0, varint id].
pub struct SetChunkEnvironments {
    pub x: i32,
    pub y: i32,
    pub z: i32,
    pub environments: Vec<u8>,
}

impl SetChunkEnvironments {
    pub fn uniform(x: i32, y: i32, z: i32, environment_id: u32) -> Self {
        let mut blob = vec![0u8]; // SectionEnvironmentsMode::Uniform
        crate::io::write_var_int(&mut blob, environment_id);
        SetChunkEnvironments { x, y, z, environments: blob }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_i32(self.x);
        w.write_i32(self.y);
        w.write_i32(self.z);
        w.write_var_int(self.environments.len() as u32);
        w.buf.extend_from_slice(&self.environments);
        w.buf
    }
}

/// VoiceConfig (452): the voice-chat configuration pushed on player
/// connect. Fixed 17-byte block: two isolated bool bytes (bit-packed
/// runs of one), codec byte, sample rate, channels, two distances,
/// max packets/sec. Values mirror VoiceRouter.sendVoiceConfig with
/// the module defaults the official server runs (32 / 4 blocks).
pub struct VoiceConfig {
    pub voice_enabled: bool,
    pub max_hearing_distance: f32,
    pub reference_distance: f32,
    pub max_packets_per_second: u8,
}

impl VoiceConfig {
    pub fn defaults() -> Self {
        VoiceConfig {
            voice_enabled: true,
            max_hearing_distance: 32.0,
            reference_distance: 4.0,
            max_packets_per_second: 50,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_bool_bits(&[self.voice_enabled]);
        w.write_u8(0); // VoiceCodec::Opus
        w.write_i32(48000);
        w.write_u8(1); // mono
        w.write_f32(self.max_hearing_distance);
        w.write_f32(self.reference_distance);
        w.write_bool_bits(&[true]); // SupportsVoiceStream
        w.write_u8(self.max_packets_per_second);
        debug_assert_eq!(w.buf.len(), 17);
        w.buf
    }
}

/// UpdateWorldMapSettings (240): world-map configuration the tracker
/// pushes when a player joins a world. One bit-packed bool byte
/// (Enabled, teleport/marker toggles) + Default/Min/Max scale floats.
pub struct UpdateWorldMapSettings {
    pub enabled: bool,
    pub allow_show_on_map_toggle: bool,
    pub allow_compass_tracking_toggle: bool,
    pub allow_creating_map_markers: bool,
}

impl UpdateWorldMapSettings {
    pub fn defaults() -> Self {
        UpdateWorldMapSettings {
            enabled: true,
            allow_show_on_map_toggle: true,
            allow_compass_tracking_toggle: true,
            allow_creating_map_markers: true,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_bool_bits(&[
            self.enabled,
            false, // AllowTeleportToCoordinates
            false, // AllowTeleportToMarkers
            self.allow_show_on_map_toggle,
            self.allow_compass_tracking_toggle,
            self.allow_creating_map_markers,
            false, // AllowRemovingOtherPlayersMarkers
        ]);
        w.write_f32(32.0); // DefaultScale
        w.write_f32(2.0); // MinScale
        w.write_f32(256.0); // MaxScale
        debug_assert_eq!(w.buf.len(), 13);
        w.buf
    }
}
