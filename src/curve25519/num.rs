use std::ops::{Div, DivAssign};

use crate::segmented_int::{SegmentedInt, SegmentedIntDescriptor};

pub type Num = SegmentedInt<Curve25519Descriptor>;

pub struct Curve25519Descriptor;

impl SegmentedIntDescriptor for Curve25519Descriptor {
	type SegmentType = u128;

	const SEGMENT_SIZE: u16 = 51;
	const CARRY_FACTOR: u128 = 19;
	const SEGMENT_MASK: u128 = 0x0007_ffff_ffff_ffff;
	const ZERO: u128 = 0;
	const ONE: u128 = 1;
}

impl Num {
	const ZERO: Self = Self {segments: [0, 0, 0, 0, 0]};
	const ONE: Self = Self {segments: [1, 0, 0, 0, 0]};

	fn recip(self) -> Self {
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
