#![cfg_attr(not(feature = "std"), no_std)]

pub mod chacha20;
pub mod poly1305;
pub mod sha2;

#[doc(inline)]
pub use curve25519::ed25519;

#[doc(inline)]
pub use curve25519::x25519;

mod curve25519;
mod segmented_int;
