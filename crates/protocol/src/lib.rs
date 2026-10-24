//! Hytale protocol implementation (release patchline, build 258), written
//! from the official shared-source protocol definitions. No game assets or
//! Hypixel code are included; layouts are re-implemented from the published
//! definitions.

pub mod frame;
pub mod io;
pub mod packets;

pub use frame::{encode_frame, FrameDecoder};
pub use io::{ProtoError, Reader, Result, Writer};
pub use packets::{Connect, HostAddress, InsecurePlayerOptions, RequestInsecurePlayerOptions};
