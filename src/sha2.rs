pub fn sha224(msg: &[u8]) -> [u8; 28] {
	let initial_hash_vals = [
		0xc1059ed8,
		0x367cd507,
		0x3070dd17,
		0xf70e5939,
		0xffc00b31,
		0x68581511,
		0x64f98fa7,
		0xbefa4fa4,
	];

	let final_hash_vals = sha_small::sha_internal(initial_hash_vals, msg);

	let mut out = [0; 28];

	for i in 0 .. 7 {
		out[4 * i .. 4 * (i + 1)].copy_from_slice(&final_hash_vals[i].to_be_bytes());
	}

	out
}

pub fn sha256(msg: &[u8]) -> [u8; 32] {
	let initial_hash_vals = [
		0x6a09e667,
		0xbb67ae85,
		0x3c6ef372,
		0xa54ff53a,
		0x510e527f,
		0x9b05688c,
		0x1f83d9ab,
		0x5be0cd19,
	];

	let final_hash_vals = sha_small::sha_internal(initial_hash_vals, msg);

	let mut out = [0; 32];

	for i in 0 .. 8 {
		out[4 * i .. 4 * (i + 1)].copy_from_slice(&final_hash_vals[i].to_be_bytes());
	}

	out
}

pub fn sha384(msg: &[u8]) -> [u8; 48] {
	let initial_hash_vals = [
		0xcbbb9d5dc1059ed8,
		0x629a292a367cd507,
		0x9159015a3070dd17,
		0x152fecd8f70e5939,
		0x67332667ffc00b31,
		0x8eb44a8768581511,
		0xdb0c2e0d64f98fa7,
		0x47b5481dbefa4fa4,
	];

	let final_hash_vals = sha_big::sha_internal(initial_hash_vals, msg);

	let mut out = [0; 48];

	for i in 0 .. 6 {
		out[8 * i .. 8 * (i + 1)].copy_from_slice(&final_hash_vals[i].to_be_bytes());
	}

	out
}

pub fn sha512(msg: &[u8]) -> [u8; 64] {
	let initial_hash_vals = [
		0x6a09e667f3bcc908,
		0xbb67ae8584caa73b,
		0x3c6ef372fe94f82b,
		0xa54ff53a5f1d36f1,
		0x510e527fade682d1,
		0x9b05688c2b3e6c1f,
		0x1f83d9abfb41bd6b,
		0x5be0cd19137e2179,
	];

	let final_hash_vals = sha_big::sha_internal(initial_hash_vals, msg);

	let mut out = [0; 64];

	for i in 0 .. 8 {
		out[8 * i .. 8 * (i + 1)].copy_from_slice(&final_hash_vals[i].to_be_bytes());
	}

	out
}

mod sha_small {
	use std::convert::TryInto;

	const ROUND_CONSTANTS: [u32; 64] = [
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	];

	pub fn sha_internal(initial_hash_vals: [u32; 8], msg: &[u8]) -> [u32; 8] {
		let byte_length: u64 = msg.len().try_into().unwrap();

		// check that the original message has length less than 2 ** 64 bits
		assert!(byte_length < (1u64 << 61));

		// everything is processed in 512-bit = 64-byte chunks

		let excess = msg.len() % 64;

		let mut final_blocks = [0; 128];

		final_blocks[0 .. excess].copy_from_slice(&msg[msg.len() - excess ..]);
		final_blocks[excess] = 0x80;

		// if the excess + 0x80 + the u64 bit length is more than 64 bytes,
		// we need 2 blocks - otherwise we can get by with only 1 final block
		let len_final_blocks = if excess + 9 <= 64 {64} else {128};

		// cut the final block(s) to the amount actually used
		let final_blocks = &mut final_blocks[.. len_final_blocks];

		let bit_length = byte_length * 8;
		final_blocks[len_final_blocks - 8 ..].copy_from_slice(&bit_length.to_be_bytes());

		let mut hash_vals = initial_hash_vals;

		for chunk in msg.chunks_exact(64) {
			sha_block(&mut hash_vals, chunk.try_into().unwrap());
		}

		for chunk in final_blocks.chunks_exact(64) {
			sha_block(&mut hash_vals, chunk.try_into().unwrap());
		}

		hash_vals
	}

	fn right_rotate(val: u32, rotation: u8) -> u32 {
		(val >> rotation) | (val << (32 - rotation))
	}

	fn mix_shift(val: u32, rotation_a: u8, rotation_b: u8, shift: u8) -> u32 {
		right_rotate(val, rotation_a) ^ right_rotate(val, rotation_b) ^ (val >> shift)
	}

	fn mix_rotate(val: u32, rotation_a: u8, rotation_b: u8, rotation_c: u8) -> u32 {
		right_rotate(val, rotation_a) ^ right_rotate(val, rotation_b) ^ right_rotate(val, rotation_c)
	}

	fn sha_block(hash_vals: &mut [u32; 8], chunk: &[u8; 64]) {
		let mut message_schedule = [0; 64];

		for i in 0 .. 16 {
			let bytes: &[u8; 4] = chunk[4 * i .. 4 * (i + 1)].try_into().unwrap();
			message_schedule[i] = u32::from_be_bytes(*bytes);
		}

		for i in 16 .. 64 {
			message_schedule[i] = message_schedule[i - 16]
				.wrapping_add(mix_shift(message_schedule[i - 15], 7, 18, 3))
				.wrapping_add(message_schedule[i - 7])
				.wrapping_add(mix_shift(message_schedule[i - 2], 17, 19, 10));
		}

		let mut working_vars = *hash_vals;

		for i in 0 .. 64 {
			let [a, b, c, d, e, f, g, h] = working_vars;

			let s1 = mix_rotate(e, 6, 11, 25);
			let ch = (e & f) ^ (!e & g);
			let t1 = h
				.wrapping_add(s1)
				.wrapping_add(ch)
				.wrapping_add(ROUND_CONSTANTS[i])
				.wrapping_add(message_schedule[i]);
			let s0 = mix_rotate(a, 2, 13, 22);
			let maj = (a & b) ^ (a & c) ^ (b & c);
			let t2 = s0.wrapping_add(maj);

			working_vars = [
				t1.wrapping_add(t2),
				a,
				b,
				c,
				d.wrapping_add(t1),
				e,
				f,
				g,
			];
		}

		for i in 0 .. 8 {
			hash_vals[i] = hash_vals[i].wrapping_add(working_vars[i]);
		}
	}
}

// SHA-512 is annoyingly similar enough to SHA-256 to make you want to
// abstract away the common logic, then instantiate it once for each

// but it's also annoyingly different enough to make it a lot easier
// to just copy-paste the code and change what you need :/

mod sha_big {
	use std::convert::TryInto;

	const ROUND_CONSTANTS: [u64; 80] = [
		0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
		0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
		0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
		0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
		0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
		0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
		0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
		0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
		0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
		0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
		0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
		0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
		0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
		0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
		0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
		0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
	];

	pub fn sha_internal(initial_hash_vals: [u64; 8], msg: &[u8]) -> [u64; 8] {
		let byte_length: u128 = msg.len().try_into().unwrap();

		// check that the original message has length less than 2 ** 128 bits
		assert!(byte_length < (1u128 << 125));

		// everything is processed in 1024-bit = 128-byte chunks

		let excess = msg.len() % 128;

		let mut final_blocks = [0; 256];

		final_blocks[0 .. excess].copy_from_slice(&msg[msg.len() - excess ..]);
		final_blocks[excess] = 0x80;

		// if the excess + 0x80 + the u128 bit length is more than 128 bytes,
		// we need 2 blocks - otherwise we can get by with only 1 final block
		let len_final_blocks = if excess + 17 <= 128 {128} else {256};

		// cut the final block(s) to the amount actually used
		let final_blocks = &mut final_blocks[.. len_final_blocks];

		let bit_length = byte_length * 8;
		final_blocks[len_final_blocks - 16 ..].copy_from_slice(&bit_length.to_be_bytes());

		let mut hash_vals = initial_hash_vals;

		for chunk in msg.chunks_exact(128) {
			sha_block(&mut hash_vals, chunk.try_into().unwrap());
		}

		for chunk in final_blocks.chunks_exact(128) {
			sha_block(&mut hash_vals, chunk.try_into().unwrap());
		}

		hash_vals
	}

	fn right_rotate(val: u64, rotation: u8) -> u64 {
		(val >> rotation) | (val << (64 - rotation))
	}

	fn mix_shift(val: u64, rotation_a: u8, rotation_b: u8, shift: u8) -> u64 {
		right_rotate(val, rotation_a) ^ right_rotate(val, rotation_b) ^ (val >> shift)
	}

	fn mix_rotate(val: u64, rotation_a: u8, rotation_b: u8, rotation_c: u8) -> u64 {
		right_rotate(val, rotation_a) ^ right_rotate(val, rotation_b) ^ right_rotate(val, rotation_c)
	}

	fn sha_block(hash_vals: &mut [u64; 8], chunk: &[u8; 128]) {
		let mut message_schedule = [0; 80];

		for i in 0 .. 16 {
			let bytes: &[u8; 8] = chunk[8 * i .. 8 * (i + 1)].try_into().unwrap();
			message_schedule[i] = u64::from_be_bytes(*bytes);
		}

		for i in 16 .. 80 {
			message_schedule[i] = message_schedule[i - 16]
				.wrapping_add(mix_shift(message_schedule[i - 15], 1, 8, 7))
				.wrapping_add(message_schedule[i - 7])
				.wrapping_add(mix_shift(message_schedule[i - 2], 19, 61, 6));
		}

		let mut working_vars = *hash_vals;

		for i in 0 .. 80 {
			let [a, b, c, d, e, f, g, h] = working_vars;

			let s1 = mix_rotate(e, 14, 18, 41);
			let ch = (e & f) ^ (!e & g);
			let t1 = h
				.wrapping_add(s1)
				.wrapping_add(ch)
				.wrapping_add(ROUND_CONSTANTS[i])
				.wrapping_add(message_schedule[i]);
			let s0 = mix_rotate(a, 28, 34, 39);
			let maj = (a & b) ^ (a & c) ^ (b & c);
			let t2 = s0.wrapping_add(maj);

			working_vars = [
				t1.wrapping_add(t2),
				a,
				b,
				c,
				d.wrapping_add(t1),
				e,
				f,
				g,
			];
		}

		for i in 0 .. 8 {
			hash_vals[i] = hash_vals[i].wrapping_add(working_vars[i]);
		}
	}
}

#[cfg(test)]
fn format_hash<I: AsRef<[u8]>>(
	hasher: impl FnOnce(&[u8]) -> I,
	input: &[u8],
) -> String {
	use std::fmt::Write;

	let mut out = String::new();

	for &byte in hasher(input).as_ref() {
		write!(out, "{:>02x}", byte).unwrap();
	}

	out
}

#[test]
fn test_empty_inputs() {
	assert_eq!(
		format_hash(sha224, b""),
		"d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
	);

	assert_eq!(
		format_hash(sha256, b""),
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	);

	assert_eq!(
		format_hash(sha384, b""),
		"38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
	);

	assert_eq!(
		format_hash(sha512, b""),
		"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
	);
}
