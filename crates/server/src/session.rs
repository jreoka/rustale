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

use std::sync::Arc;

use rustale_protocol::packets::ids;
use rustale_protocol::packets::ClientTeleport;
use rustale_protocol::setup::{
    empty_registry_init_packets, item_categories_init, update_translations_init, ConnectAccept,
    ItemCategory, RequestAssets, ServerInfo, SubCategoryDefinition, ViewRadius, WorldLoadProgress,
    WorldSettings,
};
use rustale_protocol::world::{
    uniform_section_data, AddToServerPlayerList, ClientReady, JoinWorld, ServerPlayerListPlayer,
    SetChunk, SetChunkEnvironments, SetColumn, SetClientId, SetFluids,
    VoiceConfig, UpdateWorldMapSettings,
    SetEntitySeed, SetTimeDilation, SetUpdateRate, UpdateFeatures, UpdatePostFxSettings,
    UpdateSunSettings, WorldGameplayConfig, HEIGHT_SECTIONS,
};
use rustale_protocol::{
    Asset, AuthGrant, AuthToken, Connect, FormattedMessage, InsecurePlayerOptions, ServerAuthToken,
    ServerDisconnect,
};

/// The stock pack's common-asset index (`<sha256> <path>` per line),
/// embedded from the client's own install. WorldSettings declares these
/// as required; the client mounts the files it already has by hash,
/// which is what makes its texture/model asset lookups resolve.
fn required_assets() -> &'static [Asset] {
    static ASSETS: std::sync::OnceLock<Vec<Asset>> = std::sync::OnceLock::new();
    ASSETS.get_or_init(|| {
        let index = include_str!("../assets/CommonAssetsIndex.hashes");
        index
            .lines()
            .filter_map(|line| {
                let (hash, name) = line.split_once(' ')?;
                if hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                    Some(Asset { hash: hash.to_string(), name: name.trim().to_string() })
                } else {
                    None
                }
            })
            .collect()
    })
}

/// The stock pack's en-US translation catalog, extracted from the
/// client's own install. The reference's I18nModule sends it in full
/// as the UpdateTranslations Init right after the registry burst; a
/// session in any other language falls back to it, matching
/// I18nModule.resolveLanguage's default.
fn translation_entries() -> &'static [(String, String)] {
    static ENTRIES: std::sync::OnceLock<Vec<(String, String)>> = std::sync::OnceLock::new();
    ENTRIES.get_or_init(|| {
        let json = include_str!("../assets/translations_en-US.json");
        let map: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(json).expect("embedded translations_en-US.json parses");
        map.into_iter()
            .map(|(k, v)| {
                let value = v.as_str().expect("translation values are strings").to_string();
                (k, value)
            })
            .collect()
    })
}

/// The stock item-category trees, extracted from the client's own
/// install: `UpdateItemCategories` (56, the CreativeLibrary tree) and
/// `UpdateFieldcraftCategories` (58) full Inits, replacing the
/// generic empty-array payloads in the registry burst.
fn item_category_inits() -> &'static [(i32, Vec<u8>)] {
    static INITS: std::sync::OnceLock<Vec<(i32, Vec<u8>)>> = std::sync::OnceLock::new();
    INITS.get_or_init(|| {
        let json = include_str!("../assets/categories.json");
        let root: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(json).expect("embedded categories.json parses");
        vec![
            (
                ids::UPDATE_ITEM_CATEGORIES,
                item_categories_init(&category_store(&root, "Item/Category/CreativeLibrary/")),
            ),
            (
                ids::UPDATE_FIELDCRAFT_CATEGORIES,
                item_categories_init(&category_store(&root, "Item/Category/Fieldcraft/")),
            ),
        ]
    })
}

fn category_store(
    root: &serde_json::Map<String, serde_json::Value>,
    prefix: &str,
) -> Vec<ItemCategory> {
    let mut categories: Vec<ItemCategory> = root
        .iter()
        .filter(|(path, _)| path.starts_with(prefix))
        .map(|(path, value)| {
            let stem = path
                .rsplit('/')
                .next()
                .unwrap_or(path)
                .strip_suffix(".json")
                .unwrap_or(path)
                .to_string();
            json_category(value, Some(stem))
        })
        .collect();
    categories.sort_by(|a, b| a.order.cmp(&b.order).then_with(|| a.id.cmp(&b.id)));
    categories
}

fn json_category(value: &serde_json::Value, fallback_id: Option<String>) -> ItemCategory {
    let get_str = |key: &str| value.get(key).and_then(|v| v.as_str()).map(str::to_string);
    // ItemCategory.afterDecode sorts children by Order (stable).
    let mut children: Vec<ItemCategory> = value
        .get("Children")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().map(|c| json_category(c, None)).collect())
        .unwrap_or_default();
    children.sort_by_key(|c| c.order);
    let sub_categories = value
        .get("SubCategories")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|s| SubCategoryDefinition {
                    id: s.get("Id").and_then(|v| v.as_str()).map(str::to_string),
                    name: s.get("Name").and_then(|v| v.as_str()).map(str::to_string),
                    description: s
                        .get("Description")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                    order: s.get("Order").and_then(|v| v.as_i64()).unwrap_or(0) as i32,
                })
                .collect()
        })
        .unwrap_or_default();
    ItemCategory {
        id: get_str("Id").or(fallback_id),
        name: get_str("Name"),
        icon: get_str("Icon"),
        order: value.get("Order").and_then(|v| v.as_i64()).unwrap_or(0) as i32,
        info_display_mode: match get_str("InfoDisplayMode").as_deref() {
            Some("Adjacent") => 1,
            Some("None") => 2,
            _ => 0, // Tooltip, the asset default
        },
        children,
        sub_categories,
    }
}

use crate::auth::JwtValidator;
use crate::close_code;

/// Per-connection view of the server's auth services, present only in
/// authenticated mode.
pub struct SessionAuthCtx {
    pub validator: Arc<JwtValidator>,
    /// The server session id: strict audience for client access tokens
    /// and the `aud` sent with auth-grant requests.
    pub audience: String,
    pub server_identity_token: String,
}

/// An asynchronous side effect the transport layer must perform on the
/// session's behalf (HTTP to the session service), reporting the result
/// back through `on_auth_grant` / `on_server_token`.
#[derive(Debug)]
pub enum AuthEffect {
    RequestGrant { identity_token: String },
    ExchangeGrant { grant: String },
}

/// Sections 0 and 1 are solid; the walkable surface is the top of
/// section 1, y = 63.
pub const GROUND_TOP_Y: i32 = 63;
/// Block id used for the ground sections. TODO: this must match the
/// BlockType registry sent during setup; the registry is still empty,
/// so visible ground waits on the BlockType transcription work.
pub const GROUND_BLOCK_ID: i32 = 1;
/// Cap on chunk columns streamed per axis, whatever the client asks for.
pub const MAX_CHUNK_RADIUS: i32 = 32;

/// The player's spawn position, shared by the entity spawn update
/// and the world-join ClientTeleport.
const SPAWN_POSITION: [f64; 3] = [8.0, 66.0, 8.0];

/// Serialized ChunkLightData for a uniformly full-bright section:
/// hasLight byte, root octree segment with mask 0 (no branches), and
/// eight leaf values of 0xFFFF (R/G/B/sky channels all at max 0xF).
fn full_bright_light() -> Vec<u8> {
    let mut v = Vec::with_capacity(18);
    v.push(1);
    v.push(0);
    for _ in 0..8 {
        v.extend_from_slice(&0xFFFFu16.to_le_bytes());
    }
    v
}

#[derive(Default, PartialEq, Clone, Copy, Debug)]
pub enum Phase {
    #[default]
    AwaitConnect,
    AwaitIdentity,
    /// Identity token validated; waiting for the adapter to fetch the
    /// authorization grant from the session service.
    AwaitAuthGrant,
    /// AuthGrant sent; waiting for the client's AuthToken packet.
    AwaitAuthTokenPacket,
    /// AuthToken validated; waiting for the adapter to exchange the
    /// client's server grant for a server access token.
    AwaitAuthExchange,
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
    /// An auth side effect for the transport layer to perform.
    pub effect: Option<AuthEffect>,
}

pub struct Session {
    phase: Phase,
    username: Option<String>,
    uuid: Option<[u8; 16]>,
    view_radius_blocks: Option<i32>,
    sent_assets: bool,
    chunks_sent: bool,
    teleport_sent: bool,
    auth: Option<Arc<SessionAuthCtx>>,
    /// The world identity sent in JoinWorld. Random per session: the
    /// client keys persisted per-world state (map/exploration caches)
    /// by it, and a fixed value would reuse whatever an earlier,
    /// broken run left behind.
    world_uuid: [u8; 16],
}

/// A fresh v4-layout UUID from the auth module's generator.
fn fresh_world_uuid() -> [u8; 16] {
    let s = crate::auth::new_session_id();
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    let mut b = [0u8; 16];
    for i in 0..16 {
        b[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or(0);
    }
    b
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
            teleport_sent: false,
            auth: None,
            world_uuid: fresh_world_uuid(),
        }
    }
}

impl Session {
    pub fn new() -> Self {
        Self::default()
    }

    /// A session in authenticated mode (the retail client's only path):
    /// identity comes from the client's identity JWT and the mutual-auth
    /// exchange runs before setup.
    pub fn with_auth(ctx: Arc<SessionAuthCtx>) -> Self {
        Session { auth: Some(ctx), ..Self::default() }
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
            ids::AUTH_TOKEN => self.on_auth_token(payload, &mut out),
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
                if self.auth.is_some() {
                    self.begin_authenticated(connect, out);
                } else {
                    out.packets.push((ids::REQUEST_INSECURE_PLAYER_OPTIONS, Vec::new()));
                    self.phase = Phase::AwaitIdentity;
                }
            }
            Err(e) => {
                eprintln!("[server] undecodable Connect: {e}");
                eprintln!("[server] Connect diagnosis: {}", rustale_protocol::packets::diagnose_connect(payload));
                out.drop_stream = true;
            }
        }
    }

    /// Authenticated path, from a validated Connect: validate the
    /// identity JWT locally, then ask the transport layer to fetch an
    /// authorization grant for it.
    fn begin_authenticated(&mut self, connect: Connect, out: &mut SessionOutcome) {
        let ctx = self.auth.clone().expect("authenticated session");
        let Some(token) = connect.identity_token.filter(|t| !t.is_empty()) else {
            // Mirrors the reference: an authenticated server rejects
            // tokenless ("development") connections.
            self.disconnect(out, "client.general.disconnect.serverRequiresAuthentication");
            return;
        };
        match ctx.validator.validate_identity(&token) {
            Ok(claims) => {
                println!(
                    "[server] identity validated: {} ({}) skin={}",
                    claims.username,
                    claims.uuid,
                    if claims.skin.is_some() { "present" } else { "absent" },
                );
                self.username = Some(claims.username);
                self.uuid = crate::auth::parse_uuid_str(&claims.uuid);
                self.phase = Phase::AwaitAuthGrant;
                out.effect = Some(AuthEffect::RequestGrant { identity_token: token });
            }
            Err(e) => {
                eprintln!("[server] identity token rejected: {e}");
                self.disconnect(out, "client.general.disconnect.invalidIdentityToken");
            }
        }
    }

    /// The transport layer reports the auth-grant request result.
    pub fn on_auth_grant(&mut self, grant: Option<String>) -> SessionOutcome {
        let mut out = SessionOutcome::default();
        if self.phase != Phase::AwaitAuthGrant {
            return out;
        }
        match grant {
            Some(grant) => {
                let ctx = self.auth.clone().expect("authenticated session");
                let packet = AuthGrant {
                    authorization_grant: Some(grant),
                    server_identity_token: Some(ctx.server_identity_token.clone()),
                };
                out.packets.push((ids::AUTH_GRANT, packet.serialize().unwrap_or_default()));
                self.phase = Phase::AwaitAuthTokenPacket;
            }
            None => self.disconnect(&mut out, "client.general.disconnect.authGrantFailed"),
        }
        out
    }

    fn on_auth_token(&mut self, payload: &[u8], out: &mut SessionOutcome) {
        if self.phase != Phase::AwaitAuthTokenPacket {
            self.unexpected(out, ids::AUTH_TOKEN);
            return;
        }
        let packet = match AuthToken::deserialize(payload) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[server] undecodable AuthToken: {e}");
                self.disconnect(out, "client.general.disconnect.invalidAccessToken");
                return;
            }
        };
        let ctx = self.auth.clone().expect("authenticated session");
        let Some(access) = packet.access_token.filter(|t| !t.is_empty()) else {
            self.disconnect(out, "client.general.disconnect.invalidAccessToken");
            return;
        };
        match ctx.validator.validate_access(&access, &ctx.audience) {
            Ok(claims) => {
                if crate::auth::parse_uuid_str(&claims.uuid) != self.uuid {
                    eprintln!("[server] access token UUID does not match identity token");
                    self.disconnect(out, "client.general.disconnect.tokenUuidMismatch");
                    return;
                }
                if Some(&claims.username) != self.username.as_ref() {
                    eprintln!("[server] access token username does not match identity token");
                    self.disconnect(out, "client.general.disconnect.tokenUsernameMismatch");
                    return;
                }
                println!("[server] access token validated for {}", claims.username);
                match packet.server_authorization_grant.filter(|g| !g.is_empty()) {
                    Some(grant) => {
                        self.phase = Phase::AwaitAuthExchange;
                        out.effect = Some(AuthEffect::ExchangeGrant { grant });
                    }
                    None => self.finish_auth(out, None),
                }
            }
            Err(e) => {
                eprintln!("[server] access token rejected: {e}");
                self.disconnect(out, "client.general.disconnect.invalidAccessToken");
            }
        }
    }

    /// The transport layer reports the grant-exchange result.
    pub fn on_server_token(&mut self, token: Option<String>) -> SessionOutcome {
        let mut out = SessionOutcome::default();
        if self.phase != Phase::AwaitAuthExchange {
            return out;
        }
        match token {
            Some(token) => self.finish_auth(&mut out, Some(token)),
            None => self.disconnect(&mut out, "client.general.disconnect.serverAuthFailed"),
        }
        out
    }

    /// Mutual auth complete: ServerAuthToken, then straight into setup.
    /// (ConnectAccept exists only in the insecure flow — the reference
    /// writes it solely from InitialPacketHandler's development path,
    /// and the retail client rejects it here as unexpected. Verified
    /// against the real client.)
    fn finish_auth(&mut self, out: &mut SessionOutcome, server_access_token: Option<String>) {
        let packet = ServerAuthToken { server_access_token, password_challenge: None };
        out.packets.push((ids::SERVER_AUTH_TOKEN, packet.serialize().unwrap_or_default()));
        self.setup_burst(out);
    }

    /// ConnectAccept (insecure flow only; no password -> no challenge),
    /// then the setup burst.
    fn accept_burst(&mut self, out: &mut SessionOutcome) {
        let accept = ConnectAccept { password_challenge: None };
        out.packets.push((ids::CONNECT_ACCEPT, accept.serialize().unwrap_or_default()));
        self.setup_burst(out);
    }

    /// WorldSettings + ServerInfo as setup begins.
    fn setup_burst(&mut self, out: &mut SessionOutcome) {
        let settings = WorldSettings { required_assets: Some(required_assets().to_vec()) };
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
                self.accept_burst(out);
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
                // RequestAssets lists the assets the client still NEEDS
                // (the reference serves those by hash as AssetInitialize/
                // AssetPart/AssetFinalize). Zero requested = the client
                // already holds the whole required set locally.
                let requested = req.assets.map(|a| a.len()).unwrap_or(0);
                println!(
                    "[server] RequestAssets: client requests {requested} of {} required assets",
                    required_assets().len(),
                );
                if requested > 0 {
                    eprintln!("[server] WARNING: client wants {requested} assets we cannot serve yet (no local pack files)");
                }
            }
            Err(e) => {
                eprintln!("[server] undecodable RequestAssets: {e} (continuing)");
            }
        }
        // Then the registry Init packets and the world-load pair.
        self.sent_assets = true;
        let mut burst = empty_registry_init_packets();
        // I18nModule.sendTranslations fires in this slot in the
        // reference: replace the generic empty-dict payload for
        // UpdateTranslations with the full catalog Init.
        if let Some(slot) = burst.iter_mut().find(|(id, _)| *id == ids::UPDATE_TRANSLATIONS) {
            slot.1 = update_translations_init(translation_entries());
        }
        // The stock category trees ride their registry slots the
        // same way (packets 56 and 58).
        for (id, payload) in item_category_inits() {
            if let Some(slot) = burst.iter_mut().find(|(pid, _)| pid == id) {
                slot.1 = payload.clone();
            }
        }
        out.packets.extend(burst);
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
        // addPlayer's own writes, in reference order: ClearChunks on
        // the Chunks channel (clearWorld=true on the spawn path), then
        // the PlayerConnect/module packets and the entity spawn, then
        // JoinWorld. The onFinishPlayerJoining burst (ViewRadius,
        // seed, client id, features, effects, gameplay config) waits
        // for ClientReady — see on_client_ready.
        out.chunk_packets.push((ids::CLEAR_CHUNKS, Vec::new()));
        // The world-map tracker pushes its settings when a player is
        // added; without them the client's map system has no scales.
        out.packets.push((
            ids::UPDATE_WORLD_MAP_SETTINGS,
            UpdateWorldMapSettings::defaults().serialize(),
        ));
        // VoiceModule.onPlayerConnect fires during addPlayer, before
        // JoinWorld: the baseline client log shows VoiceConfig received
        // just ahead of JoinWorldPacket.
        out.packets.push((ids::VOICE_CONFIG, VoiceConfig::defaults().serialize()));
        // ServerPlayerListModule.onPlayerConnect also fires during
        // addPlayer: the joining client receives the full player list
        // (here just itself). The reference has always sent this; we
        // never did, leaving the client's server player list empty.
        if let Some(uuid) = self.uuid {
            out.packets.push((
                ids::ADD_TO_SERVER_PLAYER_LIST,
                AddToServerPlayerList {
                    players: vec![ServerPlayerListPlayer {
                        uuid,
                        username: Some(self.username.clone().unwrap_or_default()),
                        world_uuid: Some(self.world_uuid),
                        ping: 0,
                        spectating: false,
                        lives_remaining: None,
                    }],
                }
                .serialize(),
            ));
        }
        // The player's own entity spawn precedes JoinWorld, as in the
        // reference (addPlayer adds the entity — firing sendPlayerSelf —
        // before JoinWorld is written). Network id matches SetClientId.
        out.packets.push((
            ids::ENTITY_UPDATES,
            rustale_protocol::entities::entity_updates_packet(
                rustale_protocol::entities::player_spawn_update(
                    1,
                    self.username.as_deref().unwrap_or(""),
                    SPAWN_POSITION,
                ),
            ),
        ));
        out.packets.push((
            ids::JOIN_WORLD,
            JoinWorld {
                clear_world: true,
                // The reference's spawn path passes fadeInOut=false
                // (Universe spawn: addPlayer(..., TRUE, FALSE)); the
                // official-server baseline client log confirms it:
                // "ProcessJoinWorldPacket: FadeInOut is False".
                fade_in_out: false,
                world_uuid: self.world_uuid,
                min_section_y: Some(0),
                max_section_y: Some(HEIGHT_SECTIONS - 1),
            }
            .serialize(),
        ));
        self.phase = Phase::AwaitClientReady;
    }

    /// The reference's onFinishPlayerJoining burst, sent once the
    /// client reports ready: ViewRadius (Chunks channel), entity seed,
    /// client id, time dilation, features, sun/post-fx, gameplay
    /// config, update rate — then the chunk stream.
    fn finish_joining(&mut self, out: &mut SessionOutcome) {
        // ViewRadius goes in blocks (chunks * ChunkUtil.SIZE), and it
        // must be the negotiated radius: the client waits for chunks
        // out to exactly this distance before finishing the join.
        let view_radius = ViewRadius { value: self.view_radius_blocks.unwrap_or(512) };
        out.chunk_packets.push((ids::VIEW_RADIUS, view_radius.serialize()));
        out.packets.push((ids::SET_ENTITY_SEED, SetEntitySeed { entity_seed: 0 }.serialize()));
        out.packets.push((ids::SET_CLIENT_ID, SetClientId { client_id: 1 }.serialize()));
        out.packets
            .push((ids::SET_TIME_DILATION, SetTimeDilation { time_dilation: 1.0 }.serialize()));
        out.packets.push((
            ids::UPDATE_FEATURES,
            // The reference world's feature map defaults every
            // ClientFeature to true (World: EnumMap initialized true).
            UpdateFeatures {
                features: Some(vec![(0, true), (1, true), (2, true), (3, true), (4, true)]),
            }
            .serialize()
            .unwrap_or_default(),
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
        // Diagnostic toggle: RUSTALE_NO_CHUNKS=1 skips the chunk stream
        // entirely to isolate join processing from chunk content.
        if !self.chunks_sent && std::env::var_os("RUSTALE_NO_CHUNKS").is_none() {
            self.chunks_sent = true;
            self.stream_flat_world(out);
        }
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
        if self.phase == Phase::AwaitClientReady && ready.ready_for_chunks {
            self.phase = Phase::InWorld;
            self.finish_joining(out);
        }
        // The gameplay-ready ClientReady is answered with the
        // world-join teleport (GamePacketHandler.handle(ClientReady)
        // -> TeleportSystems.queueAndSendClientTeleport): the client
        // waits for it before entering the world and acknowledges it
        // in its movement packets. First teleport id is 0.
        if ready.ready_for_gameplay && !self.teleport_sent {
            self.teleport_sent = true;
            out.packets.push((
                ids::CLIENT_TELEPORT,
                ClientTeleport {
                    teleport_id: 0,
                    position: SPAWN_POSITION,
                    body_orientation: [0.0; 3],
                    look_orientation: [0.0; 3],
                    reset_velocity: true,
                }
                .serialize(),
            ));
            println!("[server] sent world-join ClientTeleport (id 0)");
        }
    }

    /// Queue the flat test world on the Chunks stream: for every column in
    /// radius around spawn, a heightmap and all 10 sections with data
    /// (two solid ground sections, the rest uniform air).
    fn stream_flat_world(&self, out: &mut SessionOutcome) {
        let radius = self
            .view_radius_chunks()
            .unwrap_or(8)
            .clamp(1, MAX_CHUNK_RADIUS);
        let ground_data = uniform_section_data(GROUND_BLOCK_ID);
        let mut columns = 0;
        for cx in -radius..=radius {
            for cz in -radius..=radius {
                out.chunk_packets.push((
                    ids::SET_COLUMN,
                    SetColumn::uniform(cx, cz, GROUND_TOP_Y).serialize(),
                ));
                // Every section carries data: the two ground sections
                // are solid block 1, the sections above them are a
                // uniform air palette (block 0) WITH data rather than
                // null. (A null-data SetChunk leaves the client's
                // section storage uninitialized, and absent-marking
                // those sections did not resolve them either.)
                let air_data = uniform_section_data(0);
                for sy in 0..HEIGHT_SECTIONS {
                    // Local light: a uniform full-bright ChunkLightData
                    // octree (hasLight byte, root mask 0 = all eight
                    // octants are leaves, each 0xFFFF = R/G/B/sky all at
                    // the 0xF max).
                    let chunk = SetChunk {
                        x: cx,
                        y: sy,
                        z: cz,
                        local_light: Some(full_bright_light()),
                        global_light: None,
                        data: Some(if sy <= 1 {
                            ground_data.clone()
                        } else {
                            air_data.clone()
                        }),
                    };
                    if let Ok(payload) = chunk.serialize() {
                        out.chunk_packets.push((ids::SET_CHUNK, payload));
                    }
                    out.chunk_packets.push((
                        ids::SET_FLUIDS,
                        SetFluids::empty(cx, sy, cz).serialize(),
                    ));
                    out.chunk_packets.push((
                        ids::SET_CHUNK_ENVIRONMENTS,
                        SetChunkEnvironments::uniform(cx, sy, cz, 0).serialize(),
                    ));
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
    use std::time::{SystemTime, UNIX_EPOCH};

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
                ids::UPDATE_WORLD_MAP_SETTINGS,
                ids::VOICE_CONFIG,
                ids::ADD_TO_SERVER_PLAYER_LIST,
                ids::ENTITY_UPDATES,
                ids::JOIN_WORLD,
            ]
        );
        assert_eq!(s.phase(), Phase::AwaitClientReady);
        // Only ClearChunks rides the chunk stream so far.
        assert_eq!(out.chunk_packets.len(), 1);
        assert_eq!(out.chunk_packets[0].0, ids::CLEAR_CHUNKS);

        // ClientReady triggers the finish burst and the chunk stream
        // (radius was 12 chunks (384 blocks): 25 x 25 columns of
        // SetColumn + 10 x (SetChunk + SetFluids + SetChunkEnvironments),
        // preceded by ViewRadius carrying the negotiated 384 blocks).
        let out = s.handle(ids::CLIENT_READY, &[0b01]);
        assert_eq!(s.phase(), Phase::InWorld);
        let burst: Vec<i32> = out.packets.iter().map(|(id, _)| *id).collect();
        assert_eq!(
            burst,
            vec![
                ids::SET_ENTITY_SEED,
                ids::SET_CLIENT_ID,
                ids::SET_TIME_DILATION,
                ids::UPDATE_FEATURES,
                ids::UPDATE_SUN_SETTINGS,
                ids::UPDATE_POST_FX_SETTINGS,
                ids::WORLD_GAMEPLAY_CONFIG,
                ids::SET_UPDATE_RATE,
            ]
        );
        assert_eq!(out.chunk_packets.len(), 25 * 25 * 31 + 1);
        assert_eq!(out.chunk_packets[0].0, ids::VIEW_RADIUS);
        assert_eq!(out.chunk_packets[0].1, 384i32.to_le_bytes().to_vec());
        assert_eq!(out.chunk_packets[1].0, ids::SET_COLUMN);
        assert_eq!(out.chunk_packets[2].0, ids::SET_CHUNK);
        assert_eq!(out.chunk_packets[3].0, ids::SET_FLUIDS);
        assert_eq!(out.chunk_packets[4].0, ids::SET_CHUNK_ENVIRONMENTS);

        // The gameplay-ready ClientReady is answered with the
        // world-join ClientTeleport (55-byte fixed payload)...
        let out = s.handle(ids::CLIENT_READY, &[0b11]);
        assert_eq!(out.packets.len(), 1);
        assert_eq!(out.packets[0].0, ids::CLIENT_TELEPORT);
        assert_eq!(out.packets[0].1.len(), 55);
        assert!(out.chunk_packets.is_empty());

        // ...and a third ClientReady sends nothing more.
        let out = s.handle(ids::CLIENT_READY, &[0b11]);
        assert!(out.packets.is_empty());
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
    fn authenticated_exchange() {
        use base64::Engine;
        use ed25519_dalek::{Signer, SigningKey};

        let signing = SigningKey::from_bytes(&[9u8; 32]);
        let jwks = serde_json::json!({
            "keys": [{
                "kty": "OKP", "crv": "Ed25519", "kid": "k1",
                "x": base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(signing.verifying_key().as_bytes()),
            }]
        });
        let validator = Arc::new(crate::auth::JwtValidator::new("https://sessions.hytale.com".to_string()));
        validator.set_keys_from_jwks(&jwks);
        let ctx = Arc::new(SessionAuthCtx {
            validator,
            audience: "session-aud-1".to_string(),
            server_identity_token: "server-identity-jwt".to_string(),
        });

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        let mint = |claims: serde_json::Value| -> String {
            let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            let h = enc.encode(serde_json::json!({ "alg": "EdDSA", "kid": "k1" }).to_string());
            let c = enc.encode(claims.to_string());
            let input = format!("{h}.{c}");
            format!("{input}.{}", enc.encode(signing.sign(input.as_bytes()).to_bytes()))
        };
        let uuid = "523acb87-5dc9-4bbf-a419-380486de4a84";
        let identity_jwt = mint(serde_json::json!({
            "iss": "https://sessions.hytale.com", "sub": uuid,
            "iat": now, "exp": now + 3600, "scope": "hytale:client",
            "profile": { "username": "jreoka" },
        }));
        let access_jwt = mint(serde_json::json!({
            "iss": "https://sessions.hytale.com", "sub": uuid,
            "iat": now, "exp": now + 3600, "aud": "session-aud-1",
            "username": "jreoka",
        }));

        let mut s = Session::with_auth(ctx);
        let connect = Connect {
            protocol_crc: rustale_protocol::packets::PROTOCOL_CRC,
            protocol_build_number: rustale_protocol::packets::PROTOCOL_BUILD_NUMBER,
            client_version: "0.7.4".to_string(),
            client_type: 0,
            identity_token: Some(identity_jwt),
            language: "en-US".to_string(),
            referral_data: None,
            referral_source: None,
        };
        let out = s.handle(ids::CONNECT, &connect.serialize().unwrap());
        assert!(out.packets.is_empty());
        assert!(matches!(out.effect, Some(AuthEffect::RequestGrant { .. })));
        assert_eq!(s.phase(), Phase::AwaitAuthGrant);

        let out = s.on_auth_grant(Some("the-grant".to_string()));
        assert_eq!(out.packets.len(), 1);
        assert_eq!(out.packets[0].0, ids::AUTH_GRANT);
        let grant = AuthGrant::deserialize(&out.packets[0].1).unwrap();
        assert_eq!(grant.authorization_grant.as_deref(), Some("the-grant"));
        assert_eq!(grant.server_identity_token.as_deref(), Some("server-identity-jwt"));
        assert_eq!(s.phase(), Phase::AwaitAuthTokenPacket);

        let auth_token = AuthToken {
            access_token: Some(access_jwt),
            server_authorization_grant: Some("client-grant".to_string()),
        };
        let out = s.handle(ids::AUTH_TOKEN, &auth_token.serialize().unwrap());
        assert!(matches!(out.effect, Some(AuthEffect::ExchangeGrant { .. })));
        assert_eq!(s.phase(), Phase::AwaitAuthExchange);

        let out = s.on_server_token(Some("server-access-jwt".to_string()));
        let sent: Vec<i32> = out.packets.iter().map(|(id, _)| *id).collect();
        // No ConnectAccept in the authenticated flow (it is insecure-only).
        assert_eq!(sent, vec![ids::SERVER_AUTH_TOKEN, ids::WORLD_SETTINGS, ids::SERVER_INFO]);
        assert_eq!(s.phase(), Phase::AwaitSetup);

        // And setup proceeds exactly like the insecure path.
        let out = s.handle(ids::REQUEST_ASSETS, &[0x00]);
        assert_eq!(out.packets.len(), 54);
        assert_eq!(s.phase(), Phase::AwaitFinalize);
    }

    #[test]
    fn authenticated_rejects_tokenless_connect() {
        let validator = Arc::new(crate::auth::JwtValidator::new("https://sessions.hytale.com".to_string()));
        let ctx = Arc::new(SessionAuthCtx {
            validator,
            audience: "aud".to_string(),
            server_identity_token: "id".to_string(),
        });
        let mut s = Session::with_auth(ctx);
        let out = s.handle(ids::CONNECT, &connect_bytes());
        assert_eq!(out.packets.len(), 1);
        assert_eq!(out.packets[0].0, ids::SERVER_DISCONNECT);
        assert_eq!(out.close, Some(close_code::NO_ERROR));
    }

    #[test]
    fn ping_echoed_in_any_phase() {
        let mut s = Session::new();
        let out = s.handle(ids::PING, &[1, 2, 3]);
        assert_eq!(out.packets, vec![(ids::PONG, vec![1, 2, 3])]);
    }
}
