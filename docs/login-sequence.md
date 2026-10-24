# Login -> setup -> world-entry sequence (release build 258)

Traced from the reference server sources (`InitialPacketHandler`,
`PasswordPacketHandler`, `SetupPacketHandler`, `AssetRegistryLoader`,
`HytaleAssetStore`). Packet IDs from the generated protocol sources.

## 1. Initial (InitialPacketHandler)

1. C->S `Connect` (0). Server checks protocol CRC/build; mismatch closes
   the QUIC connection with application error 3 (InvalidVersion).
2. **Authenticated mode (the default, and the only mode the retail client
   accepts — it refuses the insecure handshake as a "development" server,
   verified with the real client):**
   - The server first logs ITSELF in once (OAuth device flow,
     client_id `hytale-server`, scopes `openid offline auth:server`),
     picks the account's game profile, and creates a game session
     (`POST sessions.<domain>/game-session/new`) yielding a session
     token + server identity token (stored in `auth.json`, refreshed
     via `/game-session/refresh` or the OAuth refresh token).
   - C->S `Connect` carries an identity JWT. The server validates it:
     EdDSA signature against `GET sessions.<domain>/.well-known/jwks.json`,
     issuer = the sessions URL, exp/nbf/iat within a 300 s skew, subject
     a UUID, `profile.username`, scope containing `hytale:client`.
     (No audience check on identity tokens.)
   - S->C: the server requests a grant from the session service,
     `POST /server-join/auth-grant {identityToken, aud: <server session
     id>}` (Bearer = server session token; the session id is a fresh
     UUID per server boot), then sends `AuthGrant` (11)
     `{ AuthorizationGrant, ServerIdentityToken }`.
   - C->S `AuthToken` (12) `{ AccessToken, ServerAuthorizationGrant }`.
     The server validates the access token like the identity token but
     with a STRICT audience = the server session id, and requires its
     subject/username to match the identity token's.
   - The server exchanges the client's grant:
     `POST /server-join/auth-token {authorizationGrant, x509Fingerprint}`
     (Bearer = server session token; fingerprint = base64url-no-pad
     SHA-256 of the server's TLS cert DER), then sends
     `ServerAuthToken` (13) `{ ServerAccessToken, PasswordChallenge }`
     (challenge null: no server password), followed by the step-4
     accept burst below.
3. INSECURE mode (development clients only; `RUSTALE_AUTH_MODE=offline`):
   S->C `RequestInsecurePlayerOptions` (364).
3. C->S `InsecurePlayerOptions` (363): uuid + username are required
   (missing -> `ServerDisconnect` (2) with a FormattedMessage reason).
   Skin, if present, is validated by the cosmetics module.
4. S->C `ConnectAccept` (14) `{ PasswordChallenge: byte[]? }` — null when
   no server password is set. With a challenge, the password stage runs
   (`PasswordResponse` 15 / `PasswordAccepted` 16 / `PasswordRejected` 17);
   with none it falls straight through to setup.

Timeouts guard every stage (`continueStage`); a first packet that is not
Connect gets a silent disconnect.

## 2. Setup (SetupPacketHandler)

On entry the server sends, in order:

5. S->C `WorldSettings` (20, zstd) `{ RequiredAssets: Asset[]? }` where
   `Asset = { Hash: fixed 64 ASCII, Name: string(512) }` — the common
   asset files the client must hold (from the server's common-asset pack
   index hashes).
6. S->C `ServerInfo` (223) `{ ServerName?, Motd?, MaxPlayers,
   FallbackServer: HostAddress? }`.

The client then drives:

7. C->S `RequestAssets` (23, zstd) `{ Assets: Asset[]? }` — the common
   assets the client already holds. The server replies with, in order:
   - any common-asset files the client is missing, each as
     `AssetInitialize` (24) `{ Asset, Size }`, one or more `AssetPart`
     (25, zstd) `{ Part: byte[]? }`, `AssetFinalize` (26). (Skipped
     entirely when the client's hashes match.)
   - **one init packet per asset store** (`AssetRegistryLoader.sendAssets`
     -> each store's packet generator `generateInitPacket`): the
     `Update*` packets 40-94 with `Type = Init (0)`, the full map, and
     store-specific rebuild flags (e.g. `UpdateBlockTypes` sets
     UpdateBlockTextures/UpdateModelTextures/UpdateModels/
     UpdateMapGeometry = true). These carry the server's whole registry:
     block types, items, recipes, translations, ...
   - S->C `WorldLoadProgress` (21) `{ Status: FormattedMessage?,
     PercentComplete, PercentCompleteSubitem }` with the translation key
     `client.general.worldLoad.loadingWorld`, 0, 0.
   - S->C `WorldLoadFinished` (22) (empty).
8. C->S `ViewRadius` (32) `{ Value: int }` — may arrive any time in setup;
   the server converts blocks -> chunks (ceil(value / 32)).
9. C->S `SetupFinalize` (33) (empty) — requires RequestAssets first.
   Server adds the player to the Universe -> world entry (phase 2 survey).

Any unexpected packet during initial/setup -> disconnect with
`client.general.disconnect.protocol.unexpectedPacket`.

## Our milestone-1 strategy

- WorldSettings with `RequiredAssets = null`, ServerInfo with name/motd.
- On RequestAssets: send **no** common-asset files (assume the client's
  pack matches a stock build) and an **empty-but-complete registry**: one
  Init packet for each of the 52 store-backed `Update*` types with empty
  maps and MaxId 0 — then WorldLoadProgress/WorldLoadFinished.
- Open questions only the real client can answer: whether it tolerates
  null required-assets and an empty registry, and what it does in a world
  with no block types defined. That is the milestone-1 test on real
  hardware.

## 3. World entry (World.onFinishPlayerJoining) — implemented in milestone 2

Channels are raw QUIC stream IDs, as in the reference quiche transport:
Default = the client's first bidirectional stream (id 0), Chunks = the
first server-initiated unidirectional stream (id 3), WorldMap = the
second (id 7). No channel header bytes exist; the stream id is the
channel. SetChunk/SetChunkHeightmap ride Chunks; everything else in the
join burst rides Default.

On SetupFinalize the server sends, in order: `ViewRadius` (server max),
`SetEntitySeed` (160), `SetClientId` (100), `SetTimeDilation` (30),
`UpdateFeatures` (31), `UpdateSunSettings` (360),
`UpdatePostFxSettings` (361), `WorldGameplayConfig` (185 — its three
structures serialize Combat, Player, World order), `SetUpdateRate` (29),
`JoinWorld` (104) `{ ClearWorld, FadeInOut, WorldUuid, MinSectionY=0,
MaxSectionY=9 }`.

The client answers `ClientReady` (105) `{ ReadyForChunks,
ReadyForGameplay }`; chunk streaming waits for ReadyForChunks. Chunks
are 32x32 columns of 10 sections (32^3 blocks each, world height 320).
`SetChunk` (131) `{ X, Y(section), Z, LocalLight?, GlobalLight?, Data? }`
— Data is null for all-air sections; otherwise it is three palettes
(block, filler, rotation), each a type byte (0=Empty, 1=HalfByte,
2=Byte, 3=Short) plus palette data; the Byte palette is
`[count i16][internal u8, external i32, count i16]*[one index byte per
block]`. `SetChunkHeightmap` (132) carries a fixed 1024-entry i32 array.

Our flat world: sections 0-1 solid (single block id via a uniform Byte
palette), sections 2-9 air, heightmap 63, spawn column at origin.

Known gaps for the next phases: the block id used for the ground (1) is
not yet defined in the registry we send — the BlockType packet structure
has 55 fields and must be transcribed from a real block's definition;
and the player entity's own spawn/teleport sync (EntityUpdates) has not
been surveyed yet.
