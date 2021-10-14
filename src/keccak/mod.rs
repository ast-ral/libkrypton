mod keccak_lane;
mod round_constants;

use keccak_lane::KeccakLane;
use round_constants::ROUND_CONSTANTS;

mod components {
	pub mod chi;
	pub mod iota;
	pub mod pi;
	pub mod rho;
	pub mod theta;
}

use components::chi::chi;
use components::iota::iota;
use components::pi::pi;
use components::rho::rho;
use components::theta::theta;

pub mod sha3;

pub fn keccak<T: KeccakLane>(state: &mut [[T; 5]; 5]) {
	let num_rounds = 12 + 2 * T::LOG2_WIDTH;

	for round in 0 .. num_rounds {
		theta(state);
		rho(state);
		pi(state);
		chi(state);
		iota(state, round);
	}
}
