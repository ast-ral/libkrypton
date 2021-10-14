use super::super::{KeccakLane, ROUND_CONSTANTS};

pub fn iota<T: KeccakLane>(state: &mut [[T; 5]; 5], round_number: usize) {
	state[0][0] ^= T::from_u64(ROUND_CONSTANTS[round_number]);
}
