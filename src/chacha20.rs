//! Implemented according to [IETF RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439).

use std::convert::TryInto;

fn left_rotate(val: u32, rotation: u8) -> u32 {
	(val << rotation) | (val >> (32 - rotation))
}

fn quarter_round(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32) {
	*a = a.wrapping_add(*b);
	*d ^= *a;
	*d = left_rotate(*d, 16);

	*c = c.wrapping_add(*d);
	*b ^= *c;
	*b = left_rotate(*b, 12);

	*a = a.wrapping_add(*b);
	*d ^= *a;
	*d = left_rotate(*d, 8);

	*c = c.wrapping_add(*d);
	*b ^= *c;
	*b = left_rotate(*b, 7);
}

fn double_round(state: &mut [u32; 16]) {
	let [
		s0, s1, s2, s3,
		s4, s5, s6, s7,
		s8, s9, sa, sb,
		sc, sd, se, sf,
	] = state;

	quarter_round(s0, s4, s8, sc);
	quarter_round(s1, s5, s9, sd);
	quarter_round(s2, s6, sa, se);
	quarter_round(s3, s7, sb, sf);

	quarter_round(s0, s5, sa, sf);
	quarter_round(s1, s6, sb, sc);
	quarter_round(s2, s7, s8, sd);
	quarter_round(s3, s4, s9, se);
}

fn process_state(input: &[u32; 16], output: &mut [u32; 16]) {
	output.copy_from_slice(input);

	for _ in 0 .. 10 {
		double_round(output);
	}

	for i in 0 .. 16 {
		output[i] = output[i].wrapping_add(input[i]);
	}
}

pub struct ChaCha20 {
	inner_state: [u32; 16],
	outer_state: [u32; 16],
	position_in_block: u8,
}

const MAGIC: [&[u8; 4]; 4] = [b"expa", b"nd 3", b"2-by", b"te k"];

const K0: u32 = u32::from_le_bytes(*MAGIC[0]);
const K1: u32 = u32::from_le_bytes(*MAGIC[1]);
const K2: u32 = u32::from_le_bytes(*MAGIC[2]);
const K3: u32 = u32::from_le_bytes(*MAGIC[3]);

impl ChaCha20 {
	// initializes a new chacha20 stream at block position 0
	pub fn new(key: [u8; 32], nonce: [u8; 12]) -> Self {
		let mut inner_state = [
			K0, K1, K2, K3,
			0, 0, 0, 0,
			0, 0, 0, 0,
			0, 0, 0, 0,
		];

		for i in 0 .. 8 {
			let bytes: [u8; 4] = key[4 * i .. 4 * (i + 1)].try_into().unwrap();
			inner_state[4 + i] = u32::from_le_bytes(bytes);
		}

		for i in 0 .. 3 {
			let bytes: [u8; 4] = nonce[4 * i .. 4 * (i + 1)].try_into().unwrap();
			inner_state[13 + i] = u32::from_le_bytes(bytes);
		}

		let mut outer_state = [0; 16];
		process_state(&inner_state, &mut outer_state);

		Self {
			inner_state,
			outer_state,
			position_in_block: 0,
		}
	}
}

impl Iterator for ChaCha20 {
	type Item = u8;

	fn next(&mut self) -> Option<Self::Item> {
		if self.position_in_block == 64 {
			if self.inner_state[12] == 0xffff_ffff {
				return None;
			}

			self.inner_state[12] += 1;
			self.position_in_block = 0;

			process_state(&self.inner_state, &mut self.outer_state)
		}

		let position = usize::from(self.position_in_block);
		self.position_in_block += 1;

		let word = self.outer_state[position / 4];
		Some(word.to_le_bytes()[position % 4])
	}
}

#[test]
fn rfc8439_main_test_vector() {
	let key = [
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	];

	let nonce = [
		0x00, 0x00, 0x00, 0x09,
		0x00, 0x00, 0x00, 0x4a,
		0x00, 0x00, 0x00, 0x00,
	];

	let mut iter = ChaCha20::new(key, nonce);
	let output: Vec<_> = (&mut iter).skip(64).take(64).collect();

	println!("inner_state:");
	for i in 0 .. 16 {
		println!("{:>08x}", iter.inner_state[i]);
	}

	println!("outer state:");
	for i in 0 .. 16 {
		println!("{:>08x}", iter.outer_state[i]);
	}

	let expected_output = [
		0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
		0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
		0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03,
		0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
		0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09,
		0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
		0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
		0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
	];

	assert_eq!(output, expected_output);
}

#[test]
fn rfc8439_quarter_round_test_vector() {
	let mut a = 0x11111111;
	let mut b = 0x01020304;
	let mut c = 0x9b8d6f43;
	let mut d = 0x01234567;

	quarter_round(&mut a, &mut b, &mut c, &mut d);

	assert_eq!(a, 0xea2a92f4);
	assert_eq!(b, 0xcb1cf8ce);
	assert_eq!(c, 0x4581472e);
	assert_eq!(d, 0x5881c4bb);
}
