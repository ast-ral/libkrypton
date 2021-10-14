//! An implementation of [SHA-3](https://en.wikipedia.org/wiki/SHA-3).

use super::keccak;

struct Padding<'a> {
	bytes: &'a [u8],
	done: bool,
}

impl<'a> Padding<'a> {
	fn new(bytes: &'a [u8]) -> Self {
		Self {bytes, done: false}
	}
}

impl<'a> Iterator for Padding<'a> {
	type Item = [u64; 9];

	fn next(&mut self) -> Option<Self::Item> {
		if self.done {
			return None;
		}

		let mut buf = [0; 72];
		let buf_len = buf.len();

		if self.bytes.len() >= buf_len {
			buf.copy_from_slice(&self.bytes[.. buf_len]);
			self.bytes = &self.bytes[buf_len ..];
		} else {
			buf[.. self.bytes.len()].copy_from_slice(self.bytes);
			buf[self.bytes.len()] |= 0x06;
			*buf.last_mut().unwrap() |= 0x80;
			self.done = true;
		}

		let mut out = [0; 9];

		for i in 0 .. 9 {
			out[i] = u64::from_le_bytes(buf[i * 8 ..][.. 8].try_into().unwrap());
		}

		Some(out)
	}
}

/// Returns the SHA3-512 digest of the byte slice passed to it.
pub fn sha3_512(bytes: &[u8]) -> [u8; 64] {
	let mut state = [[0; 5]; 5];

	for block in Padding::new(bytes) {
		for (i, val) in block.into_iter().enumerate() {
			state[i % 5][i / 5] ^= val;
		}

		keccak(&mut state);
	}

	let mut out = [0; 64];

	for i in 0 .. 8 {
		let val = state[i % 5][i / 5];
		out[8 * i ..][.. 8].copy_from_slice(&val.to_le_bytes());
	}

	out
}
