//! Transport-independent connection state machine: consumes decoded
//! packets, produces (packet_id, payload) replies and close decisions.
//! The QUIC layer is a thin adapter around this (framing + zstd), which
//! also makes the whole login/setup exchange testable without a live UDP
//! socket.
//!
//! Flow (traced from the reference handlers, see docs/login-sequence.md):
//! Connect -> RequestInsecurePlayerOptions -> InsecurePlayerOptions ->
//! ConnectAccept + WorldSettings + ServerInfo -> RequestAssets ->
//! registry Init packets + WorldLoadProgress + WorldLoadFinished ->
//! SetupFinalize -> in world.

use rustale_protocol::packets::ids;
use rustale_protocol::setup::{
    empty_registry_init_packets, ConnectAccept, RequestAssets, ServerInfo, ViewRadius,
    WorldLoadProgress, WorldSettings,
};
use rustale_protocol::world::{
    uniform_section_data, ClientReady, JoinWorld, SetChunk, SetChunkHeightmap, SetClientId,
    SetEntitySeed, SetTimeDilation, SetUpdateRate, UpdateFeatures, UpdatePostFxSettings,
    UpdateSunSettings, WorldGameplayConfig, HEIGHT_SECTIONS,
};
use rustale_protocol::{Connect, FormattedMessage, InsecurePlayerOptions, ServerDisconnect};

use crate::close_code;

/// The single world this server hosts, for now. Fixed UUID so the client
/// sees a stable world identity across restarts.
pub const WORLD_UUID: [u8; 16] = *b"RustaleWorld0001";
/// Sections 0 and 1 are solid; the walkable surface is the top of
/// section 1, y = 63.
pub const GROUND_TOP_Y: i32 = 63;
/// Block id used for the ground sections. TODO: this must match the
/// BlockType registry sent during setup; the registry is still empty,
/// so visible ground waits on the BlockType transcription work.
pub const GROUND_BLOCK_ID: i32 = 1;
/// Cap on chunk columns streamed per axis, whatever the client asks for.
pub const MAX_CHUNK_RADIUS: i32 = 12;

#[derive(Default, PartialEq, Clone, Copy, Debug)]
pub enum Phase {
    #[default]
    AwaitConnect,
    AwaitIdentity,
    AwaitSetup,
    AwaitFinalize,
    AwaitClientReady,
    InWorld,
}

#[derive(Default)]
pub struct SessionOutcome {
    /// (packet_id, payload) pairs to send on the Default stream, in order.
    pub packets: Vec<(i32, Vec<u8>)>,
    /// (packet_id, payload) pairs to send on the Chunks stream, in order.
    pub chunk_packets: Vec<(i32, Vec<u8>)>,
    /// If set, close the connection with this QUIC application error code
    /// after the packets above have been written.
    pub close: Option<u32>,
    /// If true, drop this stream (protocol violation).
    pub drop_stream: bool,
}

pub struct Session {
    phase: Phase,
    username: Option<String>,
    uuid: Option<[u8; 16]>,
    view_radius_blocks: Option<i32>,
    sent_assets: bool,
    chunks_sent: bool,
}

impl Default for Session {
    fn default() -> Self {
        Session {
            phase: Phase::default(),
            username: None,
            uuid: None,
            view_radius_blocks: None,
            sent_assets: false,
            chunks_sent: false,
        }
    }
}

impl Session {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn view_radius_chunks(&self) -> Option<i32> {
        // The reference converts blocks -> chunks with ceil(value / 32).
        self.view_radius_blocks.map(|v| (v as f32 / 32.0).ceil() as i32)
    }

    fn disconnect(&mut self, out: &mut SessionOutcome, message_key: &str) {
        let packet = ServerDisconnect::new_translation(message_key);
        if let Ok(payload) = packet.serialize() {
            out.packets.push((ids::SERVER_DISCONNECT, payload));
        }
        out.close = Some(close_code::NO_ERROR);
    }

    fn unexpected(&mut self, out: &mut SessionOutcome, packet_id: i32) {
        eprintln!("[server] unexpected packet {packet_id} in phase {:?}", self.phase);
        self.disconnect(out, "client.general.disconnect.protocol.unexpectedPacket");
    }

    pub fn handle(&mut self, packet_id: i32, payload: &[u8]) -> SessionOutcome {
        let mut out = SessionOutcome::default();
        match packet_id {
            // Keepalive is answered in every phase.
            ids::PING => {
                out.packets.push((ids::PONG, payload.to_vec()));
            }
            ids::CLIENT_DISCONNECT => {
                println!("[server] client disconnect packet");
                out.drop_stream = true;
            }
            ids::CONNECT => self.on_connect(payload, &mut out),
            ids::INSECURE_PLAYER_OPTIONS => self.on_insecure_options(payload, &mut out),
            ids::REQUEST_ASSETS => self.on_request_assets(payload, &mut out),
            ids::VIEW_RADIUS => match ViewRadius::deserialize(payload) {
                Ok(vr) => {
                    println!("[server] ViewRadius: {} blocks", vr.value);
                    self.view_radius_blocks = Some(vr.value);
                }
                Err(e) => eprintln!("[server] undecodable ViewRadius: {e}"),
            },
            ids::SETUP_FINALIZE => self.on_setup_finalize(&mut out),
            ids::CLIENT_READY => self.on_client_ready(payload, &mut out),
            other => {
                if matches!(self.phase, Phase::InWorld | Phase::AwaitClientReady) {
                    println!("[server] in-world packet id={other} ({} bytes)", payload.len());
                } else {
                    self.unexpected(&mut out, other);
                }
            }
        }
        out
    }

    fn on_connect(&mut self, payload: &[u8], out: &mut SessionOutcome) {
        if self.phase != Phase::AwaitConnect {
            self.unexpected(out, ids::CONNECT);
            return;
        }
        match Connect::deserialize(payload) {
            Ok(connect) => {
                println!(
                    "[server] Connect: crc={} build={} version={:?} type={} lang={:?} token={}",
                    connect.protocol_crc,
                    connect.protocol_build_number,
                    connect.client_version,
                    connect.client_type,
                    connect.language,
                    if connect.identity_token.is_some() { "present" } else { "absent" },
                );
                if connect.protocol_crc != rustale_protocol::packets::PROTOCOL_CRC
                    || connect.protocol_build_number
                        != rustale_protocol::packets::PROTOCOL_BUILD_NUMBER
                {
                    eprintln!("[server] protocol mismatch, closing with InvalidVersion");
                    out.close = Some(close_code::INVALID_VERSION);
                    return;
                }
                out.packets.push((ids::REQUEST_INSECURE_PLAYER_OPTIONS, Vec::new()));
                self.phase = Phase::AwaitIdentity;
            }
            Err(e) => {
                eprintln!("[server] undecodable Connect: {e}");
                eprintln!("[server] Connect diagnosis: {}", hytale_protocol::packets::diagnose_connect(payload));
                out.drop_stream = true;
            }
        }
    }

    fn on_insecure_options(&mut self, payload: &[u8], out: &mut SessionOutcome) {
        if self.phase != Phase::AwaitIdentity {
            self.unexpected(out, ids::INSECURE_PLAYER_OPTIONS);
            return;
        }
        match InsecurePlayerOptions::deserialize(payload) {
            Ok(opts) => {
                if opts.username.is_empty() {
                    self.disconnect(out, "client.general.disconnect.missingUsername");
                    return;
                }
                println!(
                    "[server] InsecurePlayerOptions: uuid={} username={:?} skin={}",
                    crate::format_uuid(&opts.uuid),
                    opts.username,
                    if opts.skin_raw.is_some() { "present" } else { "absent" },
                );
                self.username = Some(opts.username);
                self.uuid = Some(opts.uuid);

                // No server password -> no challenge; fall straight into
                // setup: ConnectAccept, then WorldSettings + ServerInfo.
                let accept = ConnectAccept { password_challenge: None };
                out.packets.push((ids::CONNECT_ACCEPT, accept.serialize().unwrap_or_default()));
                let settings = WorldSettings { required_assets: None };
                out.packets.push((ids::WORLD_SETTINGS, settings.serialize().unwrap_or_default()));
                let info = ServerInfo {
                    server_name: Some("Rustale".to_string()),
                    motd: None,
                    max_players: 100,
                    fallback_server: None,
                };
                out.packets.push((ids::SERVER_INFO, info.serialize().unwrap_or_default()));
                self.phase = Phase::AwaitSetup;
            }
            Err(e) => {
                eprintln!("[server] undecodable InsecurePlayerOptions: {e}");
            }
        }
    }

    fn on_request_assets(&mut self, payload: &[u8], out: &mut SessionOutcome) {
        if self.phase != Phase::AwaitSetup || self.sent_assets {
            self.unexpected(out, ids::REQUEST_ASSETS);
            return;
        }
        match RequestAssets::deserialize(payload) {
            Ok(req) => {
                let held = req.assets.map(|a| a.len()).unwrap_or(0);
                println!("[server] RequestAssets: client holds {held} common assets");
            }
            Err(e) => {
                eprintln!("[server] undecodable RequestAssets: {e} (continuing)");
            }
        }
        // We send no common-asset files (client assumed to hold the stock
        // pack), then the whole registry as empty Init packets, then the
        // world-load completion pair.
        self.sent_assets = true;
        out.packets.extend(empty_registry_init_packets());
        let progress = WorldLoadProgress {
            status: Some(FormattedMessage::translation("client.general.worldLoad.loadingWorld")),
            percent_complete: 0,
            percent_complete_subitem: 0,
        };
        out.packets.push((ids::WORLD_LOAD_PROGRESS, progress.serialize().unwrap_or_default()));
        out.packets.push((ids::WORLD_LOAD_FINISHED, Vec::new()));
        self.phase = Phase::AwaitFinalize;
    }

    fn on_setup_finalize(&mut self, out: &mut SessionOutcome) {
        if self.phase != Phase::AwaitFinalize {
            self.unexpected(out, ids::SETUP_FINALIZE);
            return;
        }
        println!(
            "[server] SetupFinalize: {} joins the world (view radius: {:?} chunks)",
            self.username.as_deref().unwrap_or("?"),
            self.view_radius_chunks(),
        );
        // The join burst, in the reference's onFinishPlayerJoining order.
        out.packets.push((ids::VIEW_RADIUS, ViewRadius { value: 32 * 32 }.serialize()));
        out.packets.push((ids::SET_ENTITY_SEED, SetEntitySeed { entity_seed: 0 }.serialize()));
        out.packets.push((ids::SET_CLIENT_ID, SetClientId { client_id: 1 }.serialize()));
        out.packets
            .push((ids::SET_TIME_DILATION, SetTimeDilation { time_dilation: 1.0 }.serialize()));
        out.packets.push((
            ids::UPDATE_FEATURES,
            UpdateFeatures { features: Some(vec![]) }.serialize().unwrap_or_default(),
        ));
        out.packets.push((
            ids::UPDATE_SUN_SETTINGS,
            UpdateSunSettings { height_percentage: 0.75, angle_radians: 0.6 }.serialize(),
        ));
        out.packets.push((
            ids::UPDATE_POST_FX_SETTINGS,
            UpdatePostFxSettings {
                global_intensity: 1.0,
                power: 1.0,
                sunshaft_scale: 1.0,
                sun_intensity: 1.0,
                sunshaft_intensity: 1.0,
            }
            .serialize(),
        ));
        out.packets.push((
            ids::WORLD_GAMEPLAY_CONFIG,
            WorldGameplayConfig::default().serialize(),
        ));
        out.packets
            .push((ids::SET_UPDATE_RATE, SetUpdateRate { updates_per_second: 20 }.serialize()));
        out.packets.push((
            ids::JOIN_WORLD,
            JoinWorld {
                clear_world: true,
                fade_in_out: true,
                world_uuid: WORLD_UUID,
                min_section_y: Some(0),
                max_section_y: Some(HEIGHT_SECTIONS - 1),
            }
            .serialize(),
        ));
        self.phase = Phase::AwaitClientReady;
    }

    fn on_client_ready(&mut self, payload: &[u8], out: &mut SessionOutcome) {
        let ready = match ClientReady::deserialize(payload) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[server] undecodable ClientReady: {e}");
                return;
            }
        };
        println!(
            "[server] ClientReady: chunks={} gameplay={}",
            ready.ready_for_chunks, ready.ready_for_gameplay
        );
        if self.phase == Phase::AwaitClientReady {
            self.phase = Phase::InWorld;
        }
        if ready.ready_for_chunks && !self.chunks_sent {
            self.chunks_sent = true;
            self.stream_flat_world(out);
        }
    }

    /// Queue the flat test world on the Chunks stream: for every column in
    /// radius around spawn, a heightmap and all 10 sections (two solid
    /// ground sections, the rest air with null data).
    fn stream_flat_world(&self, out: &mut SessionOutcome) {
        let radius = self
            .view_radius_chunks()
            .unwrap_or(8)
            .clamp(1, MAX_CHUNK_RADIUS);
        let ground_data = uniform_section_data(GROUND_BLOCK_ID);
        let mut columns = 0;
        for cx in -radius..radius {
            for cz in -radius..radius {
                out.chunk_packets.push((
                    ids::SET_CHUNK_HEIGHTMAP,
                    SetChunkHeightmap::uniform(cx, cz, GROUND_TOP_Y).serialize(),
                ));
                for sy in 0..HEIGHT_SECTIONS {
                    let chunk = if sy <= 1 {
                        SetChunk {
                            x: cx,
                            y: sy,
                            z: cz,
                            local_light: None,
                            global_light: None,
                            data: Some(ground_data.clone()),
                        }
                    } else {
                        SetChunk::air(cx, sy, cz)
                    };
                    if let Ok(payload) = chunk.serialize() {
                        out.chunk_packets.push((ids::SET_CHUNK, payload));
                    }
                }
                columns += 1;
            }
        }
        println!("[server] queued flat world: {columns} columns, radius {radius}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connect_bytes() -> Vec<u8> {
        Connect {
            protocol_crc: rustale_protocol::packets::PROTOCOL_CRC,
            protocol_build_number: rustale_protocol::packets::PROTOCOL_BUILD_NUMBER,
            client_version: "1.0.0".to_string(),
            client_type: 0,
            identity_token: None,
            language: "en-US".to_string(),
            referral_data: None,
            referral_source: None,
        }
        .serialize()
        .unwrap()
    }

    fn identity_bytes(username: &str) -> Vec<u8> {
        InsecurePlayerOptions { uuid: [0xAB; 16], username: username.to_string(), skin_raw: None }
            .serialize()
            .unwrap()
    }

    fn drive_to_setup(s: &mut Session) {
        let out = s.handle(ids::CONNECT, &connect_bytes());
        assert_eq!(out.packets.len(), 1);
        assert_eq!(out.packets[0].0, ids::REQUEST_INSECURE_PLAYER_OPTIONS);
        let out = s.handle(ids::INSECURE_PLAYER_OPTIONS, &identity_bytes("Cross"));
        let sent: Vec<i32> = out.packets.iter().map(|(id, _)| *id).collect();
        assert_eq!(sent, vec![ids::CONNECT_ACCEPT, ids::WORLD_SETTINGS, ids::SERVER_INFO]);
        assert_eq!(s.phase(), Phase::AwaitSetup);
    }

    #[test]
    fn full_setup_exchange() {
        let mut s = Session::new();
        drive_to_setup(&mut s);

        // Client may set a view radius during setup.
        s.handle(ids::VIEW_RADIUS, &ViewRadius { value: 384 }.serialize());
        assert_eq!(s.view_radius_chunks(), Some(12));

        let out = s.handle(ids::REQUEST_ASSETS, &[0x00]);
        // 52 registry Init packets + WorldLoadProgress + WorldLoadFinished.
        assert_eq!(out.packets.len(), 54);
        assert_eq!(out.packets[0].0, 40);
        assert_eq!(out.packets[51].0, 94);
        assert_eq!(out.packets[52].0, ids::WORLD_LOAD_PROGRESS);
        assert_eq!(out.packets[53].0, ids::WORLD_LOAD_FINISHED);
        assert_eq!(s.phase(), Phase::AwaitFinalize);

        let out = s.handle(ids::SETUP_FINALIZE, &[]);
        let burst: Vec<i32> = out.packets.iter().map(|(id, _)| *id).collect();
        assert_eq!(
            burst,
            vec![
                ids::VIEW_RADIUS,
                ids::SET_ENTITY_SEED,
                ids::SET_CLIENT_ID,
                ids::SET_TIME_DILATION,
                ids::UPDATE_FEATURES,
                ids::UPDATE_SUN_SETTINGS,
                ids::UPDATE_POST_FX_SETTINGS,
                ids::WORLD_GAMEPLAY_CONFIG,
                ids::SET_UPDATE_RATE,
                ids::JOIN_WORLD,
            ]
        );
        assert_eq!(s.phase(), Phase::AwaitClientReady);

        // ClientReady with chunks flag streams the flat world.
        let out = s.handle(ids::CLIENT_READY, &[0b01]);
        assert_eq!(s.phase(), Phase::InWorld);
        // radius was 12 chunks (384 blocks): (24)^2 columns * (1 heightmap + 10 sections)
        assert_eq!(out.chunk_packets.len(), 24 * 24 * 11);
        assert_eq!(out.chunk_packets[0].0, ids::SET_CHUNK_HEIGHTMAP);
        // A second ClientReady sends nothing more.
        let out = s.handle(ids::CLIENT_READY, &[0b11]);
        assert!(out.chunk_packets.is_empty());
    }

    #[test]
    fn wrong_protocol_version_closes() {
        let bad = Connect {
            protocol_crc: 1234,
            protocol_build_number: 1,
            client_version: "0.0.1".to_string(),
            client_type: 0,
            identity_token: None,
            language: "en-US".to_string(),
            referral_data: None,
            referral_source: None,
        };
        let mut s = Session::new();
        let out = s.handle(ids::CONNECT, &bad.serialize().unwrap());
        assert_eq!(out.close, Some(close_code::INVALID_VERSION));
        assert!(out.packets.is_empty());
    }

    #[test]
    fn empty_username_disconnects() {
        let mut s = Session::new();
        s.handle(ids::CONNECT, &connect_bytes());
        let out = s.handle(ids::INSECURE_PLAYER_OPTIONS, &identity_bytes(""));
        assert_eq!(out.packets.len(), 1);
        assert_eq!(out.packets[0].0, ids::SERVER_DISCONNECT);
        assert_eq!(out.close, Some(close_code::NO_ERROR));
    }

    #[test]
    fn finalize_before_assets_is_unexpected() {
        let mut s = Session::new();
        drive_to_setup(&mut s);
        let out = s.handle(ids::SETUP_FINALIZE, &[]);
        assert_eq!(out.packets[0].0, ids::SERVER_DISCONNECT);
    }

    #[test]
    fn ping_echoed_in_any_phase() {
        let mut s = Session::new();
        let out = s.handle(ids::PING, &[1, 2, 3]);
        assert_eq!(out.packets, vec![(ids::PONG, vec![1, 2, 3])]);
    }
}
