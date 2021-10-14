use super::super::KeccakLane;

pub fn rho<T: KeccakLane>(state: &mut [[T; 5]; 5]) {
	let mut rotation_amount = 0;

	let mut x = 1;
	let mut y = 0;

	for t in 0 .. 24 {
		rotation_amount += t + 1;

		state[x][y] = state[x][y].rotate(rotation_amount);

		let new_x = y;
		let new_y = (2 * x + 3 * y) % 5;

		x = new_x;
		y = new_y;
	}
}
