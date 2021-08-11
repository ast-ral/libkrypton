//! Implemented according to [IETF RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439).

use std::convert::TryInto;
use std::ops::{Add, Mul};

/// 130-bit integer type that subtracts out 2 ** 130 - 5 until results fit within the bit length.
#[derive(Copy, Clone)]
struct Limbs {
	inner: [u32; 5],
}

const LOW_26_BITS: u32 = 0x03ff_ffff;

impl Limbs {
	fn zero() -> Self {
		Self {inner: [0; 5]}
	}

	fn from_16_le_bytes(bytes: [u8; 16]) -> Self {
		let as_num = u128::from_le_bytes(bytes);
		let mut inner = [0; 5];

		for i in 0 .. 5 {
			inner[i] = (as_num >> (26 * i)) as u32 & LOW_26_BITS;
		}

		Self {inner}
	}

	fn from_complete_chunk(chunk: &[u8; 16]) -> Self {
		let mut out = Self::from_16_le_bytes(*chunk);

		// set the top bit
		out.inner[4] |= 1 << 24;

		out
	}

	fn from_incomplete_chunk(chunk: &[u8]) -> Self {
		debug_assert!(1 <= chunk.len() && chunk.len() < 16);

		let mut bytes = [0; 16];
		bytes[.. chunk.len()].copy_from_slice(chunk);

		bytes[chunk.len()] = 1;

		Self::from_16_le_bytes(bytes)
	}

	fn to_16_le_bytes(&self) -> [u8; 16] {
		// full modular reduction modulo 2 ** 130 - 5
		let mut inner = self.inner;
		let carry = carry_propagate_u32(&mut inner, 5);
		let mut inner = self.inner;
		carry_propagate_u32(&mut inner, carry * 5);

		let mut out = 0;

		for i in 0 .. 5 {
			out |= (inner[i] as u128) << (26 * i);
		}

		out.to_le_bytes()
	}
}

fn carry_propagate_u32(inner: &mut [u32; 5], mut carry: u32) -> u32 {
	for i in 0 .. 5 {
		inner[i] += carry;
		carry = inner[i] >> 26;
		inner[i] &= LOW_26_BITS;
	}

	carry
}

fn carry_propagate_u64(inner: &mut [u64; 5], mut carry: u64) -> u64 {
	for i in 0 .. 5 {
		inner[i] += carry;
		carry = inner[i] >> 26;
		inner[i] &= LOW_26_BITS as u64;
	}

	carry
}

fn to_u32_limbs(inner: &[u64; 5]) -> [u32; 5] {
	let mut out = [0; 5];

	for i in 0 .. 5 {
		out[i] = inner[i] as u32;
	}

	out
}

fn to_u64_limbs(inner: &[u32; 5]) -> [u64; 5] {
	let mut out = [0; 5];

	for i in 0 .. 5 {
		out[i] = inner[i] as u64;
	}

	out
}

impl Add for Limbs {
	type Output = Self;

	fn add(self, other: Self) -> Self {
		let mut inner = [0; 5];

		let a = self.inner;
		let b = other.inner;

		for i in 0 .. 5 {
			inner[i] = a[i] + b[i];
		}

		let mut carry = inner[4] >> 26;
		inner[4] &= LOW_26_BITS;

		for _ in 0 .. 2 {
			carry = carry_propagate_u32(&mut inner, carry * 5);
		}

		debug_assert!(carry == 0);

		Self {inner}
	}
}

impl Mul for Limbs {
	type Output = Self;

	fn mul(self, other: Self) -> Self {
		let mut inner = [0; 5];

		let a = to_u64_limbs(&self.inner);
		let b = to_u64_limbs(&other.inner);

		inner[0] = a[0] * b[0] + 5 * (a[1] * b[4] + a[2] * b[3] + a[3] * b[2] + a[4] * b[1]);
		inner[1] = a[0] * b[1] + a[1] * b[0] + 5 * (a[2] * b[4] + a[3] * b[3] + a[4] * b[2]);
		inner[2] = a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + 5 * (a[3] * b[4] + a[4] * b[3]);
		inner[3] = a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0] + 5 * a[4] * b[4];
		inner[4] = a[0] * b[4] + a[1] * b[3] + a[2] * b[2] + a[3] * b[1] + a[4] * b[0];

		let mut carry = inner[4] >> 26;
		inner[4] &= LOW_26_BITS as u64;

		for _ in 0 .. 3 {
			carry = carry_propagate_u64(&mut inner, carry * 5);
		}

		debug_assert!(carry == 0);

		Self {inner: to_u32_limbs(&inner)}
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

	let radix = Limbs::from_16_le_bytes(radix);

	let mut accum = Limbs::zero();

	while message.len() >= 16 {
		let val = Limbs::from_complete_chunk(message[0 .. 16].try_into().unwrap());
		accum = accum + val;
		accum = accum * radix;
		message = &message[16 ..];
	}

	if message.len() >= 1 {
		let val = Limbs::from_incomplete_chunk(message);
		accum = accum + val;
		accum = accum * radix;
	}

	accum = accum + Limbs::from_16_le_bytes(nonce);

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
