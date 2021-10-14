use super::super::KeccakLane;

pub fn chi<T: KeccakLane>(state: &mut [[T; 5]; 5]) {
	for y in 0 .. 5 {
		let mut new_row = [Default::default(); 5];

		for x in 0 .. 5 {
			let xp1 = (x + 1) % 5;
			let xp2 = (x + 2) % 5;

			new_row[x] = !state[xp1][y] & state[xp2][y];
		}

		for x in 0 .. 5 {
			state[x][y] ^= new_row[x];
		}
	}
}
