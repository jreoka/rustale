//! Entity sync: EntityUpdates (161) and the component-update framing.
//!
//! A ComponentUpdate is a varint subtype id followed by the subtype's
//! own block (layouts pinned to the generated serializers). An
//! EntityUpdate is: null bits, NetworkId, two offset slots (Removed,
//! Updates), then the variable block. EntityUpdates is the same shape
//! at packet level (Removed network ids, Updates).

use crate::io::Writer;

/// ComponentUpdate subtype ids (the generated deserializer's switch).
mod ct {
    pub const NAMEPLATE: u32 = 0;
    pub const MODEL: u32 = 3;
    pub const PLAYER_SKIN: u32 = 4;
    pub const EQUIPMENT: u32 = 7;
    pub const ENTITY_STATS: u32 = 8;
    pub const TRANSFORM: u32 = 9;
    pub const MOVEMENT_STATES: u32 = 10;
    pub const ENTITY_EFFECTS: u32 = 11;
    pub const INTERACTABLE: u32 = 14;
}

fn component(out: &mut Vec<u8>, type_id: u32, body: &[u8]) {
    crate::io::write_var_int(out, type_id);
    out.extend_from_slice(body);
}

/// The local player's own spawn update, mirroring the reference's
/// sendPlayerSelf for a standard player: nameplate, (null) model and
/// skin for now, empty equipment/effects/stats, transform at spawn,
/// standing movement states.
pub fn player_spawn_update(network_id: i32, username: &str, position: [f64; 3]) -> Vec<u8> {
    let mut updates: Vec<u8> = Vec::new();
    let mut count: u32 = 0;

    // InteractableUpdate: empty struct.
    component(&mut updates, ct::INTERACTABLE, &[]);
    count += 1;

    // NameplateUpdate: the text inline (single variable field).
    {
        let mut body = Vec::new();
        crate::io::write_var_int(&mut body, username.len() as u32);
        body.extend_from_slice(username.as_bytes());
        component(&mut updates, ct::NAMEPLATE, &body);
        count += 1;
    }

    // ModelUpdate: null bits (Model absent) + EntityScale; Model is the
    // single variable field and stays null in this build.
    {
        let mut body = vec![0u8];
        body.extend_from_slice(&1.0f32.to_le_bytes());
        component(&mut updates, ct::MODEL, &body);
        count += 1;
    }

    // PlayerSkinUpdate: null bits only, Skin null.
    component(&mut updates, ct::PLAYER_SKIN, &[0]);
    count += 1;

    // EquipmentUpdate: null bits + three -1 slots (ArmorIds, hands).
    {
        let mut body = vec![0u8];
        for _ in 0..3 {
            body.extend_from_slice(&(-1i32).to_le_bytes());
        }
        component(&mut updates, ct::EQUIPMENT, &body);
        count += 1;
    }

    // TransformUpdate: ModelTransform block (null bits 0x07 = position
    // and both orientations present, then 24 + 12 + 12 bytes).
    {
        let mut body = vec![0x07u8];
        for v in position {
            body.extend_from_slice(&v.to_le_bytes());
        }
        body.extend_from_slice(&[0u8; 24]); // body + look orientation
        debug_assert_eq!(body.len(), 49);
        component(&mut updates, ct::TRANSFORM, &body);
        count += 1;
    }

    // MovementStatesUpdate: 23 bit-packed bools + ExtraJumpsUsed.
    // Idle (bit 0) and OnGround (bit 15) set for a standing spawn.
    component(&mut updates, ct::MOVEMENT_STATES, &[0x01, 0x80, 0x00, 0x00]);
    count += 1;

    // EntityEffectsUpdate: empty array inline.
    component(&mut updates, ct::ENTITY_EFFECTS, &[0]);
    count += 1;

    // EntityStatsUpdate: empty dictionary inline.
    component(&mut updates, ct::ENTITY_STATS, &[0]);
    count += 1;

    // EntityUpdate framing.
    let mut w = Writer::new();
    w.write_u8(0x02); // null bits: Updates present, Removed null
    w.write_i32(network_id);
    let removed_slot = w.reserve_offset();
    let updates_slot = w.reserve_offset();
    let var_start = w.position();
    debug_assert_eq!(var_start, 13);
    w.write_offset_at(removed_slot, -1);
    w.write_offset_at(updates_slot, 0);
    w.write_var_int(count);
    w.buf.extend_from_slice(&updates);
    w.buf
}

/// EntityUpdates packet carrying a single spawn update.
pub fn entity_updates_packet(update: Vec<u8>) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u8(0x02); // null bits: Updates present, Removed null
    let removed_slot = w.reserve_offset();
    let updates_slot = w.reserve_offset();
    let var_start = w.position();
    debug_assert_eq!(var_start, 9);
    w.write_offset_at(removed_slot, -1);
    w.write_offset_at(updates_slot, 0);
    w.write_var_int(1);
    w.buf.extend_from_slice(&update);
    w.buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn player_spawn_packet_has_pinned_layout() {
        let update = player_spawn_update(1, "jreoka", [8.0, 66.0, 8.0]);
        // 13-byte EntityUpdate header + count + 90 bytes of components
        // for a 6-char name (see module docs / sendPlayerSelf order).
        assert_eq!(update.len(), 13 + 1 + 90);
        let packet = entity_updates_packet(update);
        assert_eq!(packet.len(), 9 + 1 + 104);
        assert_eq!(packet[0], 0x02);
    }
}
