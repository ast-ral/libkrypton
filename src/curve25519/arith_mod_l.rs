//! performs constant-time modular reduction over the order of the ed25519 curve group

use std::convert::TryInto;

fn mul(a: u64, b: u64) -> (u128, u128) {
	let res = a as u128 * b as u128;
	(res & 0xffff_ffff_ffff_ffff, res >> 64)
}

macro_rules! multiply_and_add {
	($val:expr, $multiplier:literal, $low:ident, $high:ident) => {
		let (low, high) = mul($val, $multiplier);
		$low += low;
		$high += high;
	};
}

macro_rules! multiply_and_add_all {
	(
		$val:expr,
		[$a:ident, $b:ident, $c:ident, $d:ident, $e:ident],
		[
			$mult_0:literal,
			$mult_1:literal,
			$mult_2:literal,
			$mult_3:literal,
		],
	) => {
		let val = $val;
		multiply_and_add!(val, $mult_0, $a, $b);
		multiply_and_add!(val, $mult_1, $b, $c);
		multiply_and_add!(val, $mult_2, $c, $d);
		multiply_and_add!(val, $mult_3, $d, $e);
	};
}

macro_rules! shunt_carry {
	($low:expr, $high:expr) => {
		$high += $low >> 64;
		$low &= 0xffff_ffff_ffff_ffff;
	};
}

macro_rules! shunt_carry_chain {
	( $_:expr $(,)? ) => {};

	( $first:expr, $second:expr, $( $tail:expr $(,)? )* ) => {
		shunt_carry!($first, $second);
		shunt_carry_chain!($second, $( $tail, )*);
	};
}

fn subtract_if_more_than(
	vars: [&mut u128; 4],
	vals: [u128; 4],
	get_wrap_bit: impl FnOnce(u128, u128, u128, u128, u128) -> u128,
	mask: u128,
) {
	let mut a_copy = *vars[0];
	let mut b_copy = *vars[1];
	let mut c_copy = *vars[2];
	let mut d_copy = *vars[3];

	let mut carry = 0;

	a_copy += vals[0];
	b_copy += vals[1];
	c_copy += vals[2];
	d_copy += vals[3];

	shunt_carry_chain!(a_copy, b_copy, c_copy, d_copy, carry);

	let wrap_bit = get_wrap_bit(a_copy, b_copy, c_copy, d_copy, carry);

	conditional_swap(wrap_bit, vars[0], &mut a_copy);
	conditional_swap(wrap_bit, vars[1], &mut b_copy);
	conditional_swap(wrap_bit, vars[2], &mut c_copy);
	conditional_swap(wrap_bit, vars[3], &mut d_copy);

	*vars[3] &= mask;
}

fn conditional_swap(swap: u128, num_a: &mut u128, num_b: &mut u128) {
	let mask = 0u128.wrapping_sub(swap);
	let xor = (*num_a ^ *num_b) & mask;
	*num_a ^= xor;
	*num_b ^= xor;
}

// TODO: make this code better
fn modular_reduction(input: [u64; 8]) -> [u64; 4] {
	let mut a = input[0] as u128;
	let mut b = input[1] as u128;
	let mut c = input[2] as u128;
	let mut d = input[3] as u128;
	let mut e = 0u128;
	let mut f = 0u128;

	multiply_and_add_all!(
		input[4],
		[a, b, c, d, e],
		[
			0xd6ec31748d98951d,
			0xc6ef5bf4737dcf70,
			0xfffffffffffffffe,
			0x0fffffffffffffff,
		],
	);

	multiply_and_add_all!(
		input[5],
		[a, b, c, d, e],
		[
			0x5812631a5cf5d3ed,
			0x93b8c838d39a5e06,
			0xb2106215d086329a,
			0x0ffffffffffffffe,
		],
	);

	multiply_and_add_all!(
		input[6],
		[a, b, c, d, e],
		[
			0x39822129a02a6271,
			0xb64a7f435e4fdd95,
			0x7ed9ce5a30a2c131,
			0x02106215d086329a,
		],
	);

	multiply_and_add_all!(
		input[7],
		[a, b, c, d, e],
		[
			0x79daf520a00acb65,
			0xe24babbe38d1d7a9,
			0xb399411b7c309a3d,
			0x0ed9ce5a30a2c131,
		],
	);

	// each iteration reduces the carry outside of the a-d registers by 16
	// we also throw in 4 extra iterations to make sure any carries fully propagate through
	// it might be possible with less than this
	for _ in 0 .. 20 {
		shunt_carry_chain!(a, b, c, d, e, f);

		let mut new_e = 0;

		multiply_and_add_all!(
			e.try_into().unwrap(),
			[a, b, c, d, new_e],
			[
				0xd6ec31748d98951d,
				0xc6ef5bf4737dcf70,
				0xfffffffffffffffe,
				0x0fffffffffffffff,
			],
		);

		e = new_e;

		multiply_and_add_all!(
			f.try_into().unwrap(),
			[a, b, c, d, e],
			[
				0x5812631a5cf5d3ed,
				0x93b8c838d39a5e06,
				0xb2106215d086329a,
				0x0ffffffffffffffe,
			],
		);

		f = 0;
	}

	shunt_carry_chain!(a, b, c, d, e, f);

	debug_assert_eq!(e, 0);
	debug_assert_eq!(f, 0);

	subtract_if_more_than(
		[&mut a, &mut b, &mut c, &mut d],
		[
			0x3f6ce72d18516098, // 2 ** 256 - 8 * l
			0x5908310ae843194d,
			0xffffffffffffffff,
			0x7fffffffffffffff,
		],
		|_, _, _, _, carry| carry & 0x01,
		0xffff_ffff_ffff_ffff,
	);

	subtract_if_more_than(
		[&mut a, &mut b, &mut c, &mut d],
		[
			0x9fb673968c28b04c, // 2 ** 255 - 4 * l
			0xac84188574218ca6,
			0xffffffffffffffff,
			0x3fffffffffffffff,
		],
		|_, _, _, d, _| d >> 63,
		0x7fff_ffff_ffff_ffff,
	);

	subtract_if_more_than(
		[&mut a, &mut b, &mut c, &mut d],
		[
			0x4fdb39cb46145826, // 2 ** 254 - 2 * l
			0xd6420c42ba10c653,
			0xffffffffffffffff,
			0x1fffffffffffffff,
		],
		|_, _, _, d, _| d >> 62,
		0x3fff_ffff_ffff_ffff,
	);

	subtract_if_more_than(
		[&mut a, &mut b, &mut c, &mut d],
		[
			0xa7ed9ce5a30a2c13, // 2 ** 253 - 1 * l
			0xeb2106215d086329,
			0xffffffffffffffff,
			0x0fffffffffffffff,
		],
		|_, _, _, d, _| d >> 61,
		0x1fff_ffff_ffff_ffff,
	);

	[
		a as u64,
		b as u64,
		c as u64,
		d as u64,
	]
}

pub fn num_mod_l_from_32_bytes(buf: &[u8; 32]) -> [u64; 4] {
	let mut u64s = [0; 8];

	for i in 0 .. 4 {
		u64s[i] = u64::from_le_bytes(buf[8 * i .. 8 * (i + 1)].try_into().unwrap());
	}

	modular_reduction(u64s)
}

pub fn num_mod_l_from_64_bytes(buf: &[u8; 64]) -> [u64; 4] {
	let mut u64s = [0; 8];

	for i in 0 .. 8 {
		u64s[i] = u64::from_le_bytes(buf[8 * i .. 8 * (i + 1)].try_into().unwrap());
	}

	modular_reduction(u64s)
}

pub fn num_mod_l_to_bytes(num: [u64; 4]) -> [u8; 32] {
	let mut out = [0; 32];

	for i in 0 .. 4 {
		out[8 * i .. 8 * (i + 1)].copy_from_slice(&num[i].to_le_bytes());
	}

	out
}

pub fn add_num_mod_l(num_a: [u64; 4], num_b: [u64; 4]) -> [u64; 4] {
	let mut result_0 = num_a[0] as u128 + num_b[0] as u128;
	let mut result_1 = num_a[1] as u128 + num_b[1] as u128;
	let mut result_2 = num_a[2] as u128 + num_b[2] as u128;
	let mut result_3 = num_a[3] as u128 + num_b[3] as u128;
	let mut carry = 0;

	shunt_carry_chain!(result_0, result_1, result_2, result_3, carry);

	modular_reduction([
		result_0 as u64,
		result_1 as u64,
		result_2 as u64,
		result_3 as u64,
		carry as u64,
		0,
		0,
		0,
	])
}

macro_rules! multiply_to_results {
	($a:expr, $b:expr, $low:ident, $high:ident) => {
		let (low, high) = mul($a, $b);
		$low += low;
		$high += high;
	};
}

pub fn mul_num_mod_l(num_a: [u64; 4], num_b: [u64; 4]) -> [u64; 4] {
	let [a0, a1, a2, a3] = num_a;
	let [b0, b1, b2, b3] = num_b;

	let mut result_0 = 0;
	let mut result_1 = 0;
	let mut result_2 = 0;
	let mut result_3 = 0;
	let mut result_4 = 0;
	let mut result_5 = 0;
	let mut result_6 = 0;
	let mut result_7 = 0;

	multiply_to_results!(a0, b0, result_0, result_1);

	multiply_to_results!(a0, b1, result_1, result_2);
	multiply_to_results!(a1, b0, result_1, result_2);

	multiply_to_results!(a0, b2, result_2, result_3);
	multiply_to_results!(a1, b1, result_2, result_3);
	multiply_to_results!(a2, b0, result_2, result_3);

	multiply_to_results!(a0, b3, result_3, result_4);
	multiply_to_results!(a1, b2, result_3, result_4);
	multiply_to_results!(a2, b1, result_3, result_4);
	multiply_to_results!(a3, b0, result_3, result_4);

	multiply_to_results!(a1, b3, result_4, result_5);
	multiply_to_results!(a2, b2, result_4, result_5);
	multiply_to_results!(a3, b1, result_4, result_5);

	multiply_to_results!(a2, b3, result_5, result_6);
	multiply_to_results!(a3, b2, result_5, result_6);

	multiply_to_results!(a3, b3, result_6, result_7);

	shunt_carry_chain!(
		result_0,
		result_1,
		result_2,
		result_3,
		result_4,
		result_5,
		result_6,
		result_7,
	);

	modular_reduction([
		result_0 as u64,
		result_1 as u64,
		result_2 as u64,
		result_3 as u64,
		result_4 as u64,
		result_5 as u64,
		result_6 as u64,
		result_7 as u64,
	])
}
