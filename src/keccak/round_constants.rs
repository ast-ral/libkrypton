const fn step_lfsr(state: u8) -> (u8, bool) {
	let new_bit = ((state & 0x8e).count_ones() & 1) as u8;
	let lfsr_output = state & 0x80 != 0;
	let new_state = (state << 1) | new_bit;

	(new_state, lfsr_output)
}

const fn compute_round_constants() -> [u64; 24] {
	let mut lfsr = 0x80;
	let mut out = [0; 24];

	let mut i = 0;

	while i < 24 {
		let mut j = 0;

		while j < 7 {
			let place = (1 << j) - 1;

			let (new_lfsr, lfsr_out) = step_lfsr(lfsr);
			lfsr = new_lfsr;

			if lfsr_out {
				out[i] |= 1 << place;
			}

			j += 1;
		}

		i += 1;
	}

	out
}

pub const ROUND_CONSTANTS: [u64; 24] = compute_round_constants();
