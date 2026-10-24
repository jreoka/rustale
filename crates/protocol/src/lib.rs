//! Hytale protocol implementation (release patchline, build 258), written
//! from the official shared-source protocol definitions. No game assets or
//! Hypixel code are included; layouts are re-implemented from the published
//! definitions.

pub mod frame;
pub mod io;
pub mod packets;
pub mod setup;
pub mod structures;
pub mod world;

pub use frame::{encode_frame, FrameDecoder};
pub use io::{ProtoError, Reader, Result, Writer};
pub use packets::{
    decode_packet_payload, encode_packet_frame, is_compressed, AuthGrant, AuthToken, Connect,
    HostAddress, InsecurePlayerOptions, RequestInsecurePlayerOptions, ServerAuthToken,
    ServerDisconnect,
};
pub use structures::{Asset, FormattedMessage};
