use super::super::KeccakLane;

pub fn pi<T: KeccakLane>(state: &mut [[T; 5]; 5]) {
	let mut new_state = [[Default::default(); 5]; 5];

	for x in 0 .. 5 {
		for y in 0 .. 5 {
			let new_x = y;
			let new_y = (2 * x + 3 * y) % 5;

			new_state[new_x][new_y] = state[x][y];
		}
	}

	*state = new_state;
}
