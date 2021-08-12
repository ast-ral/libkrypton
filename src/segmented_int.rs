//! Module for constant-time segmented integers. These are used in various
//! algorithms to represent numbers that are too big to store in a single
//! builtin integer type, but are still fixed-width. These numbers optionally
//! support being partially or fully modularly reduced by a prime slightly below
//! 2 to the power of the width of the integer.

use std::ops::{
	Add,
	AddAssign,
	BitAndAssign,
	Mul,
	MulAssign,
	Neg,
	Not,
	Shr,
	Sub,
	SubAssign,
};

// TODO: consider whether it's worth it to use a multiplication type as well as a segment type
// so that, for instance, numbers could be stored as 32-bit integers, but use 64-bit ints to multiply
pub trait SegmentedIntDescriptor {
	// I hate all the syntax options here
	// this seemed like the one where it's easiest to swap lines around
	type SegmentType:
		Add<Output = Self::SegmentType> +
		AddAssign +
		BitAndAssign +
		Copy +
		Mul<Output = Self::SegmentType> +
		Not<Output = Self::SegmentType> +
		Shr<u16, Output = Self::SegmentType> +
	;

	const SEGMENT_SIZE: u16;
	const CARRY_FACTOR: Self::SegmentType;
	const SEGMENT_MASK: Self::SegmentType;
	const ZERO: Self::SegmentType;
	const ONE: Self::SegmentType;

	const NUM_ADD_CARRIES: usize = 2;
	const NUM_MUL_CARRIES: usize = 3;
}

/// Represents an integer that's been divided into 5 equally sized segments.
/// When const generics become more of a thing, this can become generic:
/// instead of always having 5 segments, it could vary.
pub struct SegmentedInt<T: SegmentedIntDescriptor> {
	pub segments: [T::SegmentType; 5],
}

fn carry_propagate<T: SegmentedIntDescriptor>(
	segments: &mut [T::SegmentType; 5],
	mut carry: T::SegmentType,
) -> T::SegmentType {
	for i in 0 .. 5 {
		segments[i] += carry;
		carry = extract_carry::<T>(&mut segments[i]);
	}

	carry
}

fn extract_carry<T: SegmentedIntDescriptor>(
	segment: &mut T::SegmentType,
) -> T::SegmentType {
	let carry = *segment >> T::SEGMENT_SIZE;
	*segment &= T::SEGMENT_MASK;

	carry
}

impl<T: SegmentedIntDescriptor> Copy for SegmentedInt<T> {}

impl<T: SegmentedIntDescriptor> Clone for SegmentedInt<T> {
	fn clone(&self) -> Self {
		*self
	}
}

impl<T: SegmentedIntDescriptor> Add for SegmentedInt<T> {
	type Output = Self;

	fn add(self, other: Self) -> Self {
		let mut segments = [T::ZERO; 5];

		for i in 0 .. 5 {
			segments[i] = self.segments[i] + other.segments[i];
		}

		let mut carry = extract_carry::<T>(&mut segments[4]);

		for _ in 0 .. T::NUM_ADD_CARRIES {
			carry = carry_propagate::<T>(&mut segments, carry * T::CARRY_FACTOR);
		}

		Self {segments}
	}
}

impl<T: SegmentedIntDescriptor> AddAssign for SegmentedInt<T> {
	fn add_assign(&mut self, other: Self) {
		for i in 0 .. 5 {
			self.segments[i] += other.segments[i];
		}

		let mut carry = extract_carry::<T>(&mut self.segments[4]);

		for _ in 0 .. T::NUM_ADD_CARRIES {
			carry = carry_propagate::<T>(&mut self.segments, carry * T::CARRY_FACTOR);
		}
	}
}

impl<T: SegmentedIntDescriptor> Mul for SegmentedInt<T> {
	type Output = Self;

	fn mul(self, other: Self) -> Self {
		let mut segments = [T::ZERO; 5];

		let a = self.segments;
		let b = other.segments;

		segments[0] = a[0] * b[0] + T::CARRY_FACTOR * (a[1] * b[4] + a[2] * b[3] + a[3] * b[2] + a[4] * b[1]);
		segments[1] = a[0] * b[1] + a[1] * b[0] + T::CARRY_FACTOR * (a[2] * b[4] + a[3] * b[3] + a[4] * b[2]);
		segments[2] = a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + T::CARRY_FACTOR * (a[3] * b[4] + a[4] * b[3]);
		segments[3] = a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0] + T::CARRY_FACTOR * a[4] * b[4];
		segments[4] = a[0] * b[4] + a[1] * b[3] + a[2] * b[2] + a[3] * b[1] + a[4] * b[0];

		let mut carry = extract_carry::<T>(&mut segments[4]);

		for _ in 0 .. T::NUM_MUL_CARRIES {
			carry = carry_propagate::<T>(&mut segments, carry * T::CARRY_FACTOR);
		}

		Self {segments}
	}
}

impl<T: SegmentedIntDescriptor> MulAssign for SegmentedInt<T> {
	fn mul_assign(&mut self, other: Self) {
		*self = *self * other;
	}
}

impl<T: SegmentedIntDescriptor> Neg for SegmentedInt<T> {
	type Output = Self;

	fn neg(mut self) -> Self {
		let mut carry = T::ONE;

		for _ in 0 .. T::NUM_ADD_CARRIES {
			carry = carry_propagate::<T>(&mut self.segments, carry * T::CARRY_FACTOR);
		}

		for i in 0 .. 5 {
			self.segments[i] = !self.segments[i];
			self.segments[i] &= T::SEGMENT_MASK;
		}

		let mut carry = T::ONE;

		for _ in 0 .. T::NUM_ADD_CARRIES {
			carry = carry_propagate::<T>(&mut self.segments, carry) * T::CARRY_FACTOR;
		}

		self
	}
}

impl<T: SegmentedIntDescriptor> Sub for SegmentedInt<T> {
	type Output = Self;

	fn sub(self, other: Self) -> Self {
		self + (-other)
	}
}

impl<T: SegmentedIntDescriptor> SubAssign for SegmentedInt<T> {
	fn sub_assign(&mut self, other: Self) {
		*self += -other
	}
}

impl<T: SegmentedIntDescriptor> SegmentedInt<T> {
	/// Reduces the number passed in so that it's guaranteed to be below
	/// whatever prime modulus we're using.
	pub fn full_modular_reduction(&mut self) {
		// TODO: explain what this is doing
		let mut segments_copy = self.segments;
		let carry = carry_propagate::<T>(&mut segments_copy, T::CARRY_FACTOR);
		carry_propagate::<T>(&mut self.segments, carry * T::CARRY_FACTOR);
	}
}
