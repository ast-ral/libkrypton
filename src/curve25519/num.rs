use std::ops::{Div, DivAssign};

use crate::segmented_int::{SegmentedInt, SegmentedIntDescriptor};

pub type Num = SegmentedInt<Curve25519Descriptor>;

pub struct Curve25519Descriptor;

impl SegmentedIntDescriptor for Curve25519Descriptor {
	type SegmentType = u128;

	const SEGMENT_SIZE: u16 = 51;
	const CARRY_FACTOR: u128 = 19;
	const SEGMENT_MASK: u128 = LOW_51_BITS;
	const ZERO: u128 = 0;
	const ONE: u128 = 1;
}

const LOW_51_BITS: u128 = 0x0007_ffff_ffff_ffff;

impl Num {
	pub const ZERO: Self = Self {segments: [0, 0, 0, 0, 0]};
	pub const ONE: Self = Self {segments: [1, 0, 0, 0, 0]};

	pub fn recip(self) -> Self {
		let mut acc = Num::ONE;

		for _ in 0 .. 250 {
			acc = acc * acc;
			acc *= self;
		}

		for _ in 0 .. 2 {
			acc = acc * acc;
			acc = acc * acc;
			acc *= self;
		}

		acc = acc * acc;
		acc *= self;

		acc
	}

	pub fn from_bytes(mut bytes: [u8; 32]) -> Self {
		// clamp the value as specified in the RFC
		bytes[31] &= 0x7f;

		let mut len = 0;
		let mut acc = 0;
		let mut i = 0;

		let mut out = [0; 5];

		for byte in bytes {
			acc |= (byte as u128) << len;
			len += 8;

			if len >= 51 {
				len -= 51;
				out[i] = acc & LOW_51_BITS;
				acc >>= 51;
				i += 1;
			}
		}

		Self {segments: out}
	}

	pub fn to_bytes(self) -> [u8; 32] {
		let mut len = 0;
		let mut acc = 0;
		let mut i = 0;

		let mut out = [0; 32];

		for segment in self.segments {
			acc |= segment << len;
			len += 51;

			while len >= 8 {
				len -= 8;
				out[i] = acc as u8;
				acc >>= 8;
				i += 1;
			}
		}

		out[31] = acc as u8;

		out
	}
}

#[test]
fn test_from_and_to_bytes() {
	use std::io::Read;
	use crate::chacha20::ChaCha20;

	let mut stream = ChaCha20::new(*b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef", *b"ghijklmnopqr");

	for _ in 0 .. 100 {
		// get pseudorandom bytes from chacha20
		let mut data: [u8; 32] = [0; 32];
		stream.read_exact(&mut data).unwrap();

		let as_num = Num::from_bytes(data);
		let round_trip_data = as_num.to_bytes();

		// clamp the data, because we expect it to get clamped by the round-trip
		data[31] &= 0x7f;

		assert!(data == round_trip_data);
	}
}

#[test]
fn test_recip() {
	for i in 1 .. 100 {
		let num = Num {segments: [i, 0, 0, 0, 0]};
		let mut res = num.recip() * num;
		res.full_modular_reduction();

		dbg!(res.segments[0]);

		assert!(res.segments[0] == 1);

		for i in 1 .. 5 {
			assert!(res.segments[i] == 0);
		}
	}
}

impl Div for Num {
	type Output = Self;

	fn div(self, other: Self) -> Self {
		self * other.recip()
	}
}

impl DivAssign for Num {
	fn div_assign(&mut self, other: Self) {
		*self *= other.recip();
	}
}
