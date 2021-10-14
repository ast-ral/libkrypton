use super::super::KeccakLane;

pub fn theta<T: KeccakLane>(state: &mut [[T; 5]; 5]) {
	let mut parities: [T; 5] = [Default::default(); 5];

	for x in 0 .. 5 {
		for y in 0 .. 5 {
			parities[x] ^= state[x][y];
		}
	}

	for x in 0 .. 5 {
		let xm1 = (x + 4) % 5;
		let xp1 = (x + 1) % 5;

		let crossed_parities = parities[xm1] ^ parities[xp1].rotate(1);

		for y in 0 .. 5 {
			state[x][y] ^= crossed_parities;
		}
	}
}
