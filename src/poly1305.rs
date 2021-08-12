//! Implemented according to [IETF RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439).

use std::convert::TryInto;

use crate::segmented_int::{SegmentedInt, SegmentedIntDescriptor};

/// 130-bit integer type that subtracts out 2 ** 130 - 5 until results fit within the bit length.
pub type Num = SegmentedInt<Poly1305Descriptor>;

pub struct Poly1305Descriptor;

impl SegmentedIntDescriptor for Poly1305Descriptor {
	type SegmentType = u64;

	const SEGMENT_SIZE: u16 = 26;
	const CARRY_FACTOR: u64 = 5;
	const SEGMENT_MASK: u64 = LOW_26_BITS;
	const ZERO: u64 = 0;
	const ONE: u64 = 1;
}

const LOW_26_BITS: u64 = 0x03ff_ffff;

impl Num {
	fn zero() -> Self {
		Self {segments: [0; 5]}
	}

	fn from_16_le_bytes(bytes: [u8; 16]) -> Self {
		let as_num = u128::from_le_bytes(bytes);
		let mut segments = [0; 5];

		for i in 0 .. 5 {
			segments[i] = (as_num >> (26 * i)) as u64 & LOW_26_BITS;
		}

		Self {segments}
	}

	fn from_complete_chunk(chunk: &[u8; 16]) -> Self {
		let mut out = Self::from_16_le_bytes(*chunk);

		// set the top bit
		out.segments[4] |= 1 << 24;

		out
	}

	fn from_incomplete_chunk(chunk: &[u8]) -> Self {
		debug_assert!(1 <= chunk.len() && chunk.len() < 16);

		let mut bytes = [0; 16];
		bytes[.. chunk.len()].copy_from_slice(chunk);

		bytes[chunk.len()] = 1;

		Self::from_16_le_bytes(bytes)
	}

	fn to_16_le_bytes(mut self) -> [u8; 16] {
		self.full_modular_reduction();

		let mut out = 0;

		for i in 0 .. 5 {
			out |= (self.segments[i] as u128) << (26 * i);
		}

		out.to_le_bytes()
	}
}

fn clamp_radix(radix: &mut [u8; 16]) {
	radix[3] &= 0x0f;
	radix[7] &= 0x0f;
	radix[11] &= 0x0f;
	radix[15] &= 0x0f;
	radix[4] &= 0xfc;
	radix[8] &= 0xfc;
	radix[12] &= 0xfc;
}

/// Generates a Poly1305 tag for a `message`. While `radix` may be reused, `nonce`
/// *must* only be used once. Both `radix` and `nonce` *must* be kept secret.
pub fn poly1305(mut message: &[u8], mut radix: [u8; 16], nonce: [u8; 16]) -> [u8; 16] {
	clamp_radix(&mut radix);

	let radix = Num::from_16_le_bytes(radix);

	let mut accum = Num::zero();

	while message.len() >= 16 {
		let val = Num::from_complete_chunk(message[0 .. 16].try_into().unwrap());
		accum += val;
		accum *= radix;
		message = &message[16 ..];
	}

	if message.len() >= 1 {
		let val = Num::from_incomplete_chunk(message);
		accum += val;
		accum *= radix;
	}

	accum = accum + Num::from_16_le_bytes(nonce);

	accum.to_16_le_bytes()
}

/// Verifies a Poly1305 `tag` given the original `message`, `radix`, and `nonce`
/// that was used to generate it. Note that naive comparison of tags may result
/// in timing attacks. It's strongly recommended to use this function to verify
/// Poly1305 tags instead of using `==` on tags.
pub fn poly1305_verify(message: &[u8], radix: [u8; 16], nonce: [u8; 16], tag: [u8; 16]) -> bool {
	let correct_tag = poly1305(message, radix, nonce);
	constant_time_compare(tag, correct_tag)
}

fn constant_time_compare(tag_a: [u8; 16], tag_b: [u8; 16]) -> bool {
	let mut equal = true;

	for i in 0 .. 16 {
		equal &= tag_a[i] == tag_b[i];
	}

	equal
}

#[test]
fn rfc8439_main_test_vector() {
	let message = b"Cryptographic Forum Research Group";
	let radix = [
		0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
		0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
	];
	let nonce = [
		0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
		0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
	];

	let tag = poly1305(message, radix, nonce);

	print!("tag: ");
	for i in 0 .. 16 {
		print!("{:>02x}", tag[i]);
	}
	println!("");

	assert!(tag == [
		0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
		0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9,
	]);
}
