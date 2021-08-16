//! Implemented according to [IETF RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748).
//! X25519 is a variant of Diffie-Hellman key exchange, used to establish
//! a shared secret between two parties without any middleman able to discern
//! the secret.

use super::num::Num;

const BASE: Num = Num {segments: [9, 0, 0, 0, 0]};
const A24: Num = Num {segments: [121665, 0, 0, 0, 0]};

fn x25519_mult(mut scalar: [u8; 32], point: Num) -> Num {
	// clamp the scalar as specified in the RFC
	scalar[0] &= 0xf8;
	scalar[31] &= 0x7f;
	scalar[31] |= 0x40;

	let x1 = point;
	let mut x2 = Num::ONE;
	let mut z2 = Num::ZERO;
	let mut x3 = point;
	let mut z3 = Num::ONE;

	let mut swap = 0;

	for current_bit in (0 .. 255).rev() {
		let current_bit = (scalar[current_bit / 8] >> (current_bit % 8)) & 1;
		swap ^= current_bit;
		conditional_swap(swap, &mut x2, &mut x3);
		conditional_swap(swap, &mut z2, &mut z3);
		swap = current_bit;

		// this variable naming is pretty much straight out of the RFC
		// I am not to be blamed for it
		let a = x2 + z2;
		let aa = a * a;
		let b = x2 - z2;
		let bb = b * b;
		let e = aa - bb;
		let c = x3 + z3;
		let d = x3 - z3;
		let da = d * a;
		let cb = c * b;
		let dapcb = da + cb;
		let damcb = da - cb;
		x3 = dapcb * dapcb;
		z3 = x1 * damcb * damcb;
		x2 = aa * bb;
		z2 = e * (aa + A24 * e);
	}

	conditional_swap(swap, &mut x2, &mut x3);
	conditional_swap(swap, &mut z2, &mut z3);

	let mut out = x2 / z2;
	out.full_modular_reduction();
	out
}

/// Swaps the two numbers given if `swap` is 1, does nothing if `swap` is 0.
/// `swap` should never be anything besides 0 or 1.
/// Works in constant time.
fn conditional_swap(swap: u8, num_a: &mut Num, num_b: &mut Num) {
	let mask = 0u128.wrapping_sub(swap as u128);

	for i in 0 .. 5 {
		let temp = mask & (num_a.segments[i] ^ num_b.segments[i]);
		num_a.segments[i] ^= temp;
		num_b.segments[i] ^= temp;
	}
}

#[test]
fn x25519_test_vector_1() {
	let scalar = [
		0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d,
		0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46, 0x5e, 0xdd,
		0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18,
		0x50, 0x6a, 0x22, 0x44, 0xba, 0x44, 0x9a, 0xc4,
	];
	let coordinate = [
		0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb,
		0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1, 0x5f, 0x7c,
		0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b,
		0x10, 0xa9, 0x03, 0xa6, 0xd0, 0xab, 0x1c, 0x4c,
	];
	let expected_result = [
		0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90,
		0x8e, 0x94, 0xea, 0x4d, 0xf2, 0x8d, 0x08, 0x4f,
		0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7,
		0x54, 0xb4, 0x07, 0x55, 0x77, 0xa2, 0x85, 0x52,
	];

	let num = Num::from_bytes(coordinate);
	let actual_result = x25519_mult(scalar, num).to_bytes();

	assert!(actual_result == expected_result);
}

#[test]
fn x25519_test_vector_2() {
	let scalar = [
		0x4b, 0x66, 0xe9, 0xd4, 0xd1, 0xb4, 0x67, 0x3c,
		0x5a, 0xd2, 0x26, 0x91, 0x95, 0x7d, 0x6a, 0xf5,
		0xc1, 0x1b, 0x64, 0x21, 0xe0, 0xea, 0x01, 0xd4,
		0x2c, 0xa4, 0x16, 0x9e, 0x79, 0x18, 0xba, 0x0d,
	];
	let coordinate = [
		0xe5, 0x21, 0x0f, 0x12, 0x78, 0x68, 0x11, 0xd3,
		0xf4, 0xb7, 0x95, 0x9d, 0x05, 0x38, 0xae, 0x2c,
		0x31, 0xdb, 0xe7, 0x10, 0x6f, 0xc0, 0x3c, 0x3e,
		0xfc, 0x4c, 0xd5, 0x49, 0xc7, 0x15, 0xa4, 0x93,
	];
	let expected_result = [
		0x95, 0xcb, 0xde, 0x94, 0x76, 0xe8, 0x90, 0x7d,
		0x7a, 0xad, 0xe4, 0x5c, 0xb4, 0xb8, 0x73, 0xf8,
		0x8b, 0x59, 0x5a, 0x68, 0x79, 0x9f, 0xa1, 0x52,
		0xe6, 0xf8, 0xf7, 0x64, 0x7a, 0xac, 0x79, 0x57,
	];

	let num = Num::from_bytes(coordinate);
	let actual_result = x25519_mult(scalar, num).to_bytes();

	assert!(actual_result == expected_result);
}

#[test]
fn x25519_iterated_test_vector() {
	let mut scalar = [
		0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	];
	let mut coordinate = scalar;
	let expected_one_iter = [
		0x42, 0x2c, 0x8e, 0x7a, 0x62, 0x27, 0xd7, 0xbc,
		0xa1, 0x35, 0x0b, 0x3e, 0x2b, 0xb7, 0x27, 0x9f,
		0x78, 0x97, 0xb8, 0x7b, 0xb6, 0x85, 0x4b, 0x78,
		0x3c, 0x60, 0xe8, 0x03, 0x11, 0xae, 0x30, 0x79,
	];
	let expected_one_thousand_iters = [
		0x68, 0x4c, 0xf5, 0x9b, 0xa8, 0x33, 0x09, 0x55,
		0x28, 0x00, 0xef, 0x56, 0x6f, 0x2f, 0x4d, 0x3c,
		0x1c, 0x38, 0x87, 0xc4, 0x93, 0x60, 0xe3, 0x87,
		0x5f, 0x2e, 0xb9, 0x4d, 0x99, 0x53, 0x2c, 0x51,
	];

	fn one_step(scalar: &mut [u8; 32], coordinate: &mut [u8; 32]) {
		let num = Num::from_bytes(*coordinate);
		let out = x25519_mult(*scalar, num).to_bytes();

		*coordinate = *scalar;
		*scalar = out;
	}

	one_step(&mut scalar, &mut coordinate);

	assert!(scalar == expected_one_iter);

	for _ in 1 .. 1000 {
		one_step(&mut scalar, &mut coordinate);
	}

	assert!(scalar == expected_one_thousand_iters);
}

/// Given your private key (`priv_key`), returns your public key. This public
/// key may be used by any other party to compute a shared secret using
/// [`x25519_derive_secret`] or another implementation of X25519.
pub fn x25519_derive_pub_key(priv_key: [u8; 32]) -> [u8; 32] {
	x25519_mult(priv_key, BASE).to_bytes()
}

/// Given your private key (`priv_key`) and another party's public key (`pub_key`),
/// returns a shared secret that is computable by both you and the other party.
/// This shared secret is suitable to be used with a KDF to derive keys for use
/// with symmetric cryptography. Note that the other party may maliciously
/// choose their public key, and the shared secret will be all zeros in this case.
/// Otherwise, this shared secret cannot be computed by anyone without knowledge of
/// either your private key or the other party's private key.
pub fn x25519_derive_secret(priv_key: [u8; 32], pub_key: [u8; 32]) -> [u8; 32] {
	let pub_key = Num::from_bytes(pub_key);
	x25519_mult(priv_key, pub_key).to_bytes()
}

/// Determines whether the shared secret is all zeros. It's strongly recommended
/// to use this function instead of something like `==` to check if the secret is
/// all zeros because this function works in constant time, and will not leak
/// any information about the shared secret.
pub fn is_shared_secret_all_zero(secret: [u8; 32]) -> bool {
	let mut acc = 0;

	for byte in secret {
		acc |= byte;
	}

	acc == 0
}
