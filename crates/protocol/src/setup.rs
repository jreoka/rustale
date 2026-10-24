//! The setup-phase packets (ConnectAccept through SetupFinalize) plus the
//! per-asset-store Init packets. Layouts follow the generator rules
//! verified against the reference serializers:
//! - null-bits, then fixed fields in declaration order (consecutive bools
//!   bit-packed),
//! - packets with 2+ variable fields use one i32 offset slot per variable
//!   field; a packet with exactly one variable field writes it inline.

use crate::io::{ProtoError, Reader, Result, Writer};
use crate::packets::HostAddress;
use crate::structures::{Asset, FormattedMessage};

// ---------------------------------------------------------------------------
// ConnectAccept (14), server -> client. Single variable field -> inline.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectAccept {
    pub password_challenge: Option<Vec<u8>>,
}

impl ConnectAccept {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.write_u8(self.password_challenge.is_some() as u8);
        if let Some(challenge) = &self.password_challenge {
            w.write_byte_array(challenge, 64)?;
        }
        Ok(w.buf)
    }
}

// ---------------------------------------------------------------------------
// WorldSettings (20, zstd), server -> client. Single variable field.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorldSettings {
    pub required_assets: Option<Vec<Asset>>,
}

impl WorldSettings {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.write_u8(self.required_assets.is_some() as u8);
        if let Some(assets) = &self.required_assets {
            w.write_var_int(assets.len() as u32);
            for asset in assets {
                asset.serialize(&mut w)?;
            }
        }
        Ok(w.buf)
    }
}

// ---------------------------------------------------------------------------
// ServerInfo (223), server -> client. Three variable fields -> slots.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerInfo {
    pub server_name: Option<String>,
    pub motd: Option<String>,
    pub max_players: i32,
    pub fallback_server: Option<HostAddress>,
}

impl ServerInfo {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        let mut null_bits = 0u8;
        if self.server_name.is_some() {
            null_bits |= 0x01;
        }
        if self.motd.is_some() {
            null_bits |= 0x02;
        }
        if self.fallback_server.is_some() {
            null_bits |= 0x04;
        }
        w.write_u8(null_bits);
        w.write_i32(self.max_players);
        let name_slot = w.reserve_offset();
        let motd_slot = w.reserve_offset();
        let fallback_slot = w.reserve_offset();
        let var_start = w.position();
        debug_assert_eq!(var_start, 17);
        match &self.server_name {
            Some(s) => {
                w.write_offset_at(name_slot, (w.position() - var_start) as i32);
                w.write_string(s, 256)?;
            }
            None => w.write_offset_at(name_slot, -1),
        }
        match &self.motd {
            Some(s) => {
                w.write_offset_at(motd_slot, (w.position() - var_start) as i32);
                w.write_string(s, 4096)?;
            }
            None => w.write_offset_at(motd_slot, -1),
        }
        match &self.fallback_server {
            Some(addr) => {
                w.write_offset_at(fallback_slot, (w.position() - var_start) as i32);
                addr.serialize(&mut w)?;
            }
            None => w.write_offset_at(fallback_slot, -1),
        }
        Ok(w.buf)
    }
}

// ---------------------------------------------------------------------------
// WorldLoadProgress (21), server -> client. Single variable field -> inline.

#[derive(Debug, Clone, PartialEq)]
pub struct WorldLoadProgress {
    pub status: Option<FormattedMessage>,
    pub percent_complete: i32,
    pub percent_complete_subitem: i32,
}

impl WorldLoadProgress {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.write_u8(self.status.is_some() as u8);
        w.write_i32(self.percent_complete);
        w.write_i32(self.percent_complete_subitem);
        if let Some(status) = &self.status {
            w.buf.extend_from_slice(&status.serialize()?);
        }
        Ok(w.buf)
    }
}

// ---------------------------------------------------------------------------
// RequestAssets (23, zstd), client -> server. Single variable field.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestAssets {
    pub assets: Option<Vec<Asset>>,
}

impl RequestAssets {
    pub fn deserialize(buf: &[u8]) -> Result<Self> {
        if buf.is_empty() {
            return Err(ProtoError::BufferTooSmall { needed: 1, have: 0 });
        }
        let r = Reader::new(buf);
        let present = r.u8_at(0)? & 0x01 != 0;
        if !present {
            return Ok(RequestAssets { assets: None });
        }
        let mut pos = 1;
        let count = crate::io::read_var_int(buf, &mut pos)? as usize;
        if count > 4_096_000 {
            return Err(ProtoError::StringTooLong { len: count, max: 4_096_000 });
        }
        let mut assets = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            let (asset, next) = Asset::deserialize(&r, pos)?;
            assets.push(asset);
            pos = next;
        }
        Ok(RequestAssets { assets: Some(assets) })
    }
}

// ---------------------------------------------------------------------------
// Common-asset file transfer (24/25/26), server -> client.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetInitialize {
    pub asset: Asset,
    pub size: i32,
}

impl AssetInitialize {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        // Asset is the only variable field: inline, after the fixed Size.
        let mut w = Writer::new();
        w.write_i32(self.size);
        self.asset.serialize(&mut w)?;
        Ok(w.buf)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetPart {
    pub part: Option<Vec<u8>>,
}

impl AssetPart {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        w.write_u8(self.part.is_some() as u8);
        if let Some(part) = &self.part {
            w.write_byte_array(part, 1_000_000)?;
        }
        Ok(w.buf)
    }
}

// AssetFinalize (26) and WorldLoadFinished (22) and SetupFinalize (33)
// have empty payloads.

// ---------------------------------------------------------------------------
// ViewRadius (32), both directions.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ViewRadius {
    pub value: i32,
}

impl ViewRadius {
    pub fn serialize(&self) -> Vec<u8> {
        self.value.to_le_bytes().to_vec()
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self> {
        if buf.len() < 4 {
            return Err(ProtoError::BufferTooSmall { needed: 4, have: buf.len() });
        }
        Ok(ViewRadius { value: i32::from_le_bytes(buf[0..4].try_into().unwrap()) })
    }
}

// ---------------------------------------------------------------------------
// The per-store Init packets (Update* 40-94, minus the objective packets).
//
// An Init packet is: Type = Init (0), MaxId = 0 where the packet has one,
// empty collections everywhere, "removed" arrays absent, and the store's
// rebuild bool flags set (the reference generators set them on Init, e.g.
// BlockTypePacketGenerator sets all four). We reproduce that shape for
// every store so the client sees a complete, consistent, empty registry.

#[derive(Clone, Copy, PartialEq)]
enum Var {
    /// Nullable dictionary, sent present-but-empty.
    Dict,
    /// Required (non-nullable) dictionary, sent empty; no null-bit.
    RequiredDict,
    /// Nullable array of structures, sent present-but-empty.
    Arr,
    /// Nullable "removed items" string array: absent on Init.
    Removed,
}

struct UpdateSpec {
    id: i32,
    max_id: bool,
    vars: &'static [Var],
    bool_flags: usize,
}

const D: Var = Var::Dict;
const RD: Var = Var::RequiredDict;
const A: Var = Var::Arr;
const R: Var = Var::Removed;

static UPDATE_SPECS: &[UpdateSpec] = &[
    UpdateSpec { id: 40, max_id: true, vars: &[D], bool_flags: 4 },    // BlockTypes
    UpdateSpec { id: 41, max_id: true, vars: &[D], bool_flags: 0 },    // BlockHitboxes
    UpdateSpec { id: 42, max_id: true, vars: &[D], bool_flags: 0 },    // BlockSoundSets
    UpdateSpec { id: 43, max_id: true, vars: &[D], bool_flags: 0 },    // ItemSoundSets
    UpdateSpec { id: 44, max_id: false, vars: &[D], bool_flags: 0 },   // BlockParticleSets
    UpdateSpec { id: 45, max_id: false, vars: &[RD], bool_flags: 0 },  // BlockBreakingDecals
    UpdateSpec { id: 46, max_id: false, vars: &[D], bool_flags: 0 },   // BlockSets
    UpdateSpec { id: 47, max_id: true, vars: &[D], bool_flags: 0 },    // Weathers
    UpdateSpec { id: 48, max_id: false, vars: &[D], bool_flags: 0 },   // Trails
    UpdateSpec { id: 49, max_id: false, vars: &[D, R], bool_flags: 0 }, // ParticleSystems
    UpdateSpec { id: 50, max_id: false, vars: &[D, R], bool_flags: 0 }, // ParticleSpawners
    UpdateSpec { id: 51, max_id: true, vars: &[D], bool_flags: 0 },    // EntityEffects
    UpdateSpec { id: 52, max_id: false, vars: &[D], bool_flags: 0 },   // ItemPlayerAnimations
    UpdateSpec { id: 53, max_id: true, vars: &[D], bool_flags: 0 },    // Modelvfxs
    UpdateSpec { id: 54, max_id: false, vars: &[D, R], bool_flags: 2 }, // Items
    UpdateSpec { id: 55, max_id: true, vars: &[D], bool_flags: 0 },    // ItemQualities
    UpdateSpec { id: 56, max_id: false, vars: &[A], bool_flags: 0 },   // ItemCategories
    UpdateSpec { id: 57, max_id: true, vars: &[D], bool_flags: 0 },    // ItemReticles
    UpdateSpec { id: 58, max_id: false, vars: &[A], bool_flags: 0 },   // FieldcraftCategories
    UpdateSpec { id: 59, max_id: false, vars: &[D], bool_flags: 0 },   // ResourceTypes
    UpdateSpec { id: 60, max_id: false, vars: &[D, R], bool_flags: 0 }, // Recipes
    UpdateSpec { id: 61, max_id: true, vars: &[D], bool_flags: 1 },    // Environments
    UpdateSpec { id: 62, max_id: true, vars: &[D], bool_flags: 0 },    // AmbienceFX
    UpdateSpec { id: 63, max_id: true, vars: &[D], bool_flags: 0 },    // FluidFX
    UpdateSpec { id: 64, max_id: false, vars: &[D], bool_flags: 0 },   // Translations
    UpdateSpec { id: 65, max_id: true, vars: &[D], bool_flags: 0 },    // SoundEvents
    UpdateSpec { id: 66, max_id: true, vars: &[], bool_flags: 0 },     // Interactions
    UpdateSpec { id: 67, max_id: true, vars: &[D], bool_flags: 0 },    // RootInteractions
    UpdateSpec { id: 68, max_id: false, vars: &[D], bool_flags: 0 },   // UnarmedInteractions
    UpdateSpec { id: 72, max_id: true, vars: &[D], bool_flags: 0 },    // EntityStatTypes
    UpdateSpec { id: 73, max_id: true, vars: &[D], bool_flags: 0 },    // EntityUIComponents
    UpdateSpec { id: 74, max_id: true, vars: &[D], bool_flags: 0 },    // HitboxCollisionConfig
    UpdateSpec { id: 75, max_id: true, vars: &[D], bool_flags: 0 },    // RepulsionConfig
    UpdateSpec { id: 76, max_id: false, vars: &[RD], bool_flags: 0 },  // ViewBobbing
    UpdateSpec { id: 77, max_id: true, vars: &[D], bool_flags: 0 },   // CameraShake
    UpdateSpec { id: 78, max_id: false, vars: &[D], bool_flags: 0 },   // BlockGroups
    UpdateSpec { id: 79, max_id: true, vars: &[D], bool_flags: 0 },    // SoundSets
    UpdateSpec { id: 80, max_id: true, vars: &[D], bool_flags: 0 },    // AudioCategories
    UpdateSpec { id: 81, max_id: true, vars: &[D], bool_flags: 0 },    // ReverbEffects
    UpdateSpec { id: 82, max_id: true, vars: &[D], bool_flags: 0 },    // EqualizerEffects
    UpdateSpec { id: 83, max_id: true, vars: &[D], bool_flags: 0 },    // Fluids
    UpdateSpec { id: 84, max_id: true, vars: &[D], bool_flags: 0 },    // TagPatterns
    UpdateSpec { id: 85, max_id: false, vars: &[D, R], bool_flags: 0 }, // ProjectileConfigs
    UpdateSpec { id: 86, max_id: true, vars: &[D], bool_flags: 0 },   // Emotes
    UpdateSpec { id: 87, max_id: true, vars: &[D], bool_flags: 0 },    // PhysicalMaterials
    UpdateSpec { id: 88, max_id: true, vars: &[D], bool_flags: 0 },   // MusicContainers
    UpdateSpec { id: 89, max_id: true, vars: &[D], bool_flags: 0 },    // AudioStates
    UpdateSpec { id: 90, max_id: false, vars: &[D], bool_flags: 0 },   // ConnectedBlockRuleSets
    UpdateSpec { id: 91, max_id: true, vars: &[D], bool_flags: 0 },    // MusicTransitions
    UpdateSpec { id: 92, max_id: true, vars: &[D], bool_flags: 0 },    // Stingers
    UpdateSpec { id: 93, max_id: true, vars: &[D], bool_flags: 0 },    // BeamConfigs
    UpdateSpec { id: 94, max_id: true, vars: &[D], bool_flags: 0 },    // AbilityKeywords
];

fn serialize_empty_init(spec: &UpdateSpec) -> Vec<u8> {
    let mut w = Writer::new();
    // Null-bits cover the nullable variable fields, in declaration order:
    // Dict and Arr are present on Init, Removed is absent, RequiredDict has
    // no bit at all.
    let nullable: Vec<&Var> = spec.vars.iter().filter(|v| **v != Var::RequiredDict).collect();
    if !nullable.is_empty() {
        let mut bits = vec![0u8; nullable.len().div_ceil(8)];
        for (i, v) in nullable.iter().enumerate() {
            if **v != Var::Removed {
                bits[i / 8] |= 1 << (i % 8);
            }
        }
        w.buf.extend_from_slice(&bits);
    }
    w.write_u8(0); // Type = Init
    if spec.max_id {
        w.write_i32(0);
    }
    if spec.bool_flags > 0 {
        w.write_bool_bits(&vec![true; spec.bool_flags]);
    }

    let write_empty = |w: &mut Writer| w.write_var_int(0);
    if spec.vars.len() == 1 {
        // Single variable field: inline.
        match spec.vars[0] {
            Var::Dict | Var::RequiredDict | Var::Arr => write_empty(&mut w),
            Var::Removed => {}
        }
    } else if spec.vars.len() > 1 {
        let slots: Vec<usize> = spec.vars.iter().map(|_| w.reserve_offset()).collect();
        let var_start = w.position();
        for (var, slot) in spec.vars.iter().zip(slots) {
            match var {
                Var::Dict | Var::Arr => {
                    w.write_offset_at(slot, (w.position() - var_start) as i32);
                    write_empty(&mut w);
                }
                Var::RequiredDict => {
                    w.write_offset_at(slot, (w.position() - var_start) as i32);
                    write_empty(&mut w);
                }
                Var::Removed => w.write_offset_at(slot, -1),
            }
        }
    }
    w.buf
}

/// All 52 store Init packets as (packet_id, payload) pairs, in ID order.
pub fn empty_registry_init_packets() -> Vec<(i32, Vec<u8>)> {
    UPDATE_SPECS.iter().map(|s| (s.id, serialize_empty_init(s))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_accept_no_password() {
        assert_eq!(ConnectAccept { password_challenge: None }.serialize().unwrap(), vec![0x00]);
        let with = ConnectAccept { password_challenge: Some(vec![7u8; 32]) }.serialize().unwrap();
        assert_eq!(with.len(), 1 + 1 + 32);
        assert_eq!(with[0], 0x01);
        assert_eq!(with[1], 32);
    }

    #[test]
    fn world_settings_null_and_empty() {
        assert_eq!(WorldSettings { required_assets: None }.serialize().unwrap(), vec![0x00]);
        assert_eq!(
            WorldSettings { required_assets: Some(vec![]) }.serialize().unwrap(),
            vec![0x01, 0x00]
        );
    }

    #[test]
    fn update_block_types_empty_init_bytes() {
        let packets = empty_registry_init_packets();
        assert_eq!(packets.len(), 52);
        let (_, payload) = packets.iter().find(|(id, _)| *id == 40).unwrap();
        // nullbits(dict present) | Type=Init | MaxId=0 | 4 bool flags | count 0
        assert_eq!(payload, &vec![0x01, 0x00, 0, 0, 0, 0, 0x0F, 0x00]);
    }

    #[test]
    fn update_items_empty_init_bytes() {
        let packets = empty_registry_init_packets();
        let (_, payload) = packets.iter().find(|(id, _)| *id == 54).unwrap();
        // nullbits(items present, removed absent) | Type | boolbits(2) |
        // slots [0, -1] | count 0
        assert_eq!(
            payload,
            &vec![0x01, 0x00, 0x03, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]
        );
    }

    #[test]
    fn update_interactions_has_no_nullbits() {
        let packets = empty_registry_init_packets();
        let (_, payload) = packets.iter().find(|(id, _)| *id == 66).unwrap();
        assert_eq!(payload, &vec![0x00, 0, 0, 0, 0]); // Type + MaxId only
    }

    #[test]
    fn request_assets_round_trip_shape() {
        // null | no payload; and present with one asset.
        assert_eq!(RequestAssets::deserialize(&[0x00]).unwrap(), RequestAssets { assets: None });
        let mut w = Writer::new();
        w.write_u8(1);
        w.write_var_int(1);
        Asset { hash: "b".repeat(64), name: "Pack".to_string() }.serialize(&mut w).unwrap();
        let parsed = RequestAssets::deserialize(&w.buf).unwrap();
        assert_eq!(parsed.assets.unwrap().len(), 1);
    }
}
