pub mod ed25519;
pub mod x25519;

mod arith_mod_l;
mod num;

/// Swaps the two numbers given if `swap` is 1, does nothing if `swap` is 0.
/// `swap` should never be anything besides 0 or 1.
/// Works in constant time.
fn conditional_swap(swap: u8, num_a: &mut num::Num, num_b: &mut num::Num) {
	let mask = 0u128.wrapping_sub(swap as u128);

	for i in 0 .. 5 {
		let temp = mask & (num_a.segments[i] ^ num_b.segments[i]);
		num_a.segments[i] ^= temp;
		num_b.segments[i] ^= temp;
	}
}
