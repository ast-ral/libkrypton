#![cfg_attr(not(feature = "std"), no_std)]

#![doc(html_logo_url = "https://raw.githubusercontent.com/ast-ral/libkrypton/master/logo.svg")]

// to prevent broken links when building documentation in #![no_std] mode
#[cfg(all(not(feature = "std"), doc))]
extern crate std;

pub mod chacha20;
pub mod poly1305;
pub mod sha2;

#[doc(inline)]
pub use curve25519::ed25519;

#[doc(inline)]
pub use curve25519::x25519;

mod curve25519;
mod segmented_int;
