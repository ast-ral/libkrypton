use core::ops::{BitAnd, BitXor, BitXorAssign, Not};

pub trait KeccakLane:
	BitAnd<Output = Self> +
	BitXor<Output = Self> +
	BitXorAssign +
	Not<Output = Self> +
	Default +
	Sized +
	Copy +
{
	const LOG2_WIDTH: usize;

	fn rotate(self, amount: u32) -> Self;
	fn from_u64(val: u64) -> Self;
}

impl KeccakLane for bool {
	const LOG2_WIDTH: usize = 0;

	fn rotate(self, _: u32) -> Self {
		self
	}

	fn from_u64(val: u64) -> Self {
		val & 1 != 0
	}
}

impl KeccakLane for u8 {
	const LOG2_WIDTH: usize = 3;

	fn rotate(self, amount: u32) -> Self {
		self.rotate_left(amount)
	}

	fn from_u64(val: u64) -> Self {
		val as Self
	}
}

impl KeccakLane for u16 {
	const LOG2_WIDTH: usize = 4;

	fn rotate(self, amount: u32) -> Self {
		self.rotate_left(amount)
	}

	fn from_u64(val: u64) -> Self {
		val as Self
	}
}

impl KeccakLane for u32 {
	const LOG2_WIDTH: usize = 5;

	fn rotate(self, amount: u32) -> Self {
		self.rotate_left(amount)
	}

	fn from_u64(val: u64) -> Self {
		val as Self
	}
}

impl KeccakLane for u64 {
	const LOG2_WIDTH: usize = 6;

	fn rotate(self, amount: u32) -> Self {
		self.rotate_left(amount)
	}

	fn from_u64(val: u64) -> Self {
		val
	}
}
