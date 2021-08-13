//! Implemented according to [IETF RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439).
//! ChaCha20 is typically used as a symmetric stream cipher with a 256-bit key
//! and a 96-bit nonce. See the [`ChaCha20`] docs for usage.

use std::convert::TryInto;
use std::io::{self, Read, Seek, SeekFrom};

fn left_rotate(val: u32, rotation: u8) -> u32 {
	(val << rotation) | (val >> (32 - rotation))
}

fn quarter_round(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32) {
	*a = a.wrapping_add(*b);
	*d ^= *a;
	*d = left_rotate(*d, 16);

	*c = c.wrapping_add(*d);
	*b ^= *c;
	*b = left_rotate(*b, 12);

	*a = a.wrapping_add(*b);
	*d ^= *a;
	*d = left_rotate(*d, 8);

	*c = c.wrapping_add(*d);
	*b ^= *c;
	*b = left_rotate(*b, 7);
}

fn double_round(state: &mut [u32; 16]) {
	let [
		s0, s1, s2, s3,
		s4, s5, s6, s7,
		s8, s9, sa, sb,
		sc, sd, se, sf,
	] = state;

	quarter_round(s0, s4, s8, sc);
	quarter_round(s1, s5, s9, sd);
	quarter_round(s2, s6, sa, se);
	quarter_round(s3, s7, sb, sf);

	quarter_round(s0, s5, sa, sf);
	quarter_round(s1, s6, sb, sc);
	quarter_round(s2, s7, s8, sd);
	quarter_round(s3, s4, s9, se);
}

fn process_state(input: &[u32; 16], output: &mut [u32; 16]) {
	output.copy_from_slice(input);

	for _ in 0 .. 10 {
		double_round(output);
	}

	for i in 0 .. 16 {
		output[i] = output[i].wrapping_add(input[i]);
	}
}

/// Creating a ChaCha20 instance can be done through [`ChaCha20::new`].
/// With an instance, you can encrypt/decrypt binary data with the [`ChaCha20::crypt`]
/// function, or read raw pseudorandom data using the [`Iterator<Item = u8>`](Iterator)
/// implementation or the [`Read`] implementation.
pub struct ChaCha20 {
	inner_state: [u32; 16],
	outer_state: [u32; 16],
	position_in_block: u8,
}

const MAGIC: [&[u8; 4]; 4] = [b"expa", b"nd 3", b"2-by", b"te k"];

const K0: u32 = u32::from_le_bytes(*MAGIC[0]);
const K1: u32 = u32::from_le_bytes(*MAGIC[1]);
const K2: u32 = u32::from_le_bytes(*MAGIC[2]);
const K3: u32 = u32::from_le_bytes(*MAGIC[3]);

impl ChaCha20 {
	/// Initializes a new ChaCha20 stream at position 0.
	/// The nonce here *must not* be reused to encrypt different messages.
	pub fn new(key: [u8; 32], nonce: [u8; 12]) -> Self {
		let mut inner_state = [
			K0, K1, K2, K3,
			0, 0, 0, 0,
			0, 0, 0, 0,
			0, 0, 0, 0,
		];

		for i in 0 .. 8 {
			let bytes: [u8; 4] = key[4 * i .. 4 * (i + 1)].try_into().unwrap();
			inner_state[4 + i] = u32::from_le_bytes(bytes);
		}

		for i in 0 .. 3 {
			let bytes: [u8; 4] = nonce[4 * i .. 4 * (i + 1)].try_into().unwrap();
			inner_state[13 + i] = u32::from_le_bytes(bytes);
		}

		let mut outer_state = [0; 16];
		process_state(&inner_state, &mut outer_state);

		Self {
			inner_state,
			outer_state,
			position_in_block: 0,
		}
	}

	/// Encrypts or decrypts data using bytes drawn from the current location of the stream.
	/// Since ChaCha20 is a stream cipher using xor, the same function can be used
	/// for both encryption and decryption of data.

	/// # Panics
	/// * Panics if the ChaCha20 instance runs out of bytes to encrypt/decrypt with.
	///   In this case, the out buffer's contents are unspecified.

	/// # Examples
	/// ```
	/// # use libkrypton::chacha20::ChaCha20;
	/// #
	/// # let key = [0; 32];
	/// # let nonce = [0; 12];
	/// let mut data = *b"hello";
	///
	/// let mut stream = ChaCha20::new(key, nonce);
	/// stream.crypt(&mut data);
	/// // data now contains ciphertext and can be transferred e.g. across the network
	///
	/// // to decrypt:
	/// // create a new ChaCha20 stream with the same parameters
	/// let mut stream = ChaCha20::new(key, nonce);
	/// // and use the same crypt function on the ciphertext
	/// stream.crypt(&mut data);
	/// // data now contains the original plaintext
	///
	/// assert!(data == *b"hello");
	/// ```
	pub fn crypt(&mut self, mut data: &mut [u8]) {
		let mut buf = [0; 1024];

		while data.len() != 0 {
			let consuming = buf.len().min(data.len());
			let buf = &mut buf[0 .. consuming];

			self.read_exact(buf).unwrap();

			for i in 0 .. consuming {
				data[i] ^= buf[i];
			}

			data = &mut data[consuming ..];
		}
	}

	/// This is provided as an alternative to the [`Seek`] implementation.
	/// Sets the position of the stream as bytes from the start.
	/// If the position is greater than the length of the stream,
	/// it gets clamped down to the length of the stream.
	pub fn set_pos(&mut self, pos: u64) {
		match (pos / 64).try_into().ok() {
			Some(block) => {
				self.inner_state[12] = block;
				self.position_in_block = (pos % 64) as u8;
			}

			None => {
				self.inner_state[12] = u32::MAX;
				self.position_in_block = 64;
			}
		}

		process_state(&self.inner_state, &mut self.outer_state);
	}

	pub fn get_pos(&self) -> u64 {
		self.inner_state[12] as u64 * 64 + self.position_in_block as u64
	}
}

impl Iterator for ChaCha20 {
	type Item = u8;

	fn next(&mut self) -> Option<Self::Item> {
		if self.position_in_block == 64 {
			if self.inner_state[12] == u32::MAX {
				return None;
			}

			self.inner_state[12] += 1;
			self.position_in_block = 0;

			process_state(&self.inner_state, &mut self.outer_state);
		}

		let position = usize::from(self.position_in_block);
		self.position_in_block += 1;

		let word = self.outer_state[position / 4];
		Some(word.to_le_bytes()[position % 4])
	}
}

impl Read for ChaCha20 {
	fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
		let mut written = 0;

		// write until we get to the end of the block
		while buf.len() != 0 /* && self.position_in_block != 64 */ {
			buf[0] = match self.next() {
				Some(x) => x,
				None => return Ok(written),
			};
			buf = &mut buf[1 ..];
			written += 1;
		}

		// write whole 64-byte chunks while we can
		while buf.len() >= 64 {
			if self.inner_state[12] == u32::MAX {
				return Ok(written);
			}

			self.inner_state[12] += 1;
			process_state(&self.inner_state, &mut self.outer_state);

			for i in 0 .. 16 {
				let [a, b, c, d] = self.outer_state[i].to_le_bytes();

				buf[0] = a;
				buf[1] = b;
				buf[2] = c;
				buf[3] = d;

				buf = &mut buf[4 ..];
			}

			written += 64;
		}

		// write the rest of the buffer
		while buf.len() != 0 {
			buf[0] = match self.next() {
				Some(x) => x,
				None => return Ok(written),
			};
			buf = &mut buf[1 ..];
			written += 1;
		}

		Ok(written)
	}
}

fn offset_u64(a: u64, b: i64) -> u64 {
	match b {
		0 => a,
		1 ..= i64::MAX => a + b as u64,
		i64::MIN ..= -1 => a - ((-b) as u64),
	}
}

impl Seek for ChaCha20 {
	fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
		match pos {
			SeekFrom::Start(pos) => {
				self.set_pos(pos);
				Ok(self.get_pos())
			}

			SeekFrom::Current(diff) => {
				let pos = self.get_pos();
				self.set_pos(offset_u64(pos, diff));
				Ok(self.get_pos())
			}

			SeekFrom::End(diff) => {
				let end = 64 * (u32::MAX as u64 + 1);
				self.set_pos(offset_u64(end, diff));
				Ok(self.get_pos())
			}
		}
	}
}

#[test]
fn rfc8439_main_test_vector() {
	let key = [
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	];

	let nonce = [
		0x00, 0x00, 0x00, 0x09,
		0x00, 0x00, 0x00, 0x4a,
		0x00, 0x00, 0x00, 0x00,
	];

	let mut iter = ChaCha20::new(key, nonce);
	let output: Vec<_> = (&mut iter).skip(64).take(64).collect();

	println!("inner_state:");
	for i in 0 .. 16 {
		println!("{:>08x}", iter.inner_state[i]);
	}

	println!("outer state:");
	for i in 0 .. 16 {
		println!("{:>08x}", iter.outer_state[i]);
	}

	let expected_output = [
		0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
		0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
		0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03,
		0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
		0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09,
		0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
		0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
		0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
	];

	assert_eq!(output, expected_output);
}

#[test]
fn rfc8439_quarter_round_test_vector() {
	let mut a = 0x11111111;
	let mut b = 0x01020304;
	let mut c = 0x9b8d6f43;
	let mut d = 0x01234567;

	quarter_round(&mut a, &mut b, &mut c, &mut d);

	assert_eq!(a, 0xea2a92f4);
	assert_eq!(b, 0xcb1cf8ce);
	assert_eq!(c, 0x4581472e);
	assert_eq!(d, 0x5881c4bb);
}

#[test]
fn check_read_vs_iterator() {
	let mut stream = ChaCha20::new([0; 32], [0; 12]);

	// set_pos(32) here to check handing of Read when it's not 64-byte aligned

	let buf_read = &mut [0; 1024];
	stream.set_pos(32);
	stream.read_exact(buf_read).unwrap();

	let buf_iter = &mut [0; 1024];
	stream.set_pos(32);
	buf_iter.iter_mut().for_each(|x| *x = stream.next().unwrap());

	assert!(buf_read == buf_iter);
}

#[test]
fn verify_encrypt_decrypt_round_trip() {
	let data = &mut [0; 1024];
	let mut stream = ChaCha20::new([0; 32], [0; 12]);

	stream.crypt(data);
	stream.rewind().unwrap();
	stream.crypt(data);

	assert!(*data == [0; 1024]);
}

#[test]
fn check_read_vs_verify() {
	// crypt on zero bytes should be the same as the read stream

	let mut stream = ChaCha20::new([0; 32], [0; 12]);

	// use 1024 + 512 here to test buffers that aren't a multiple of 1024

	let buf_read = &mut [0; 1536];
	stream.read_exact(buf_read).unwrap();

	stream.rewind().unwrap();

	let buf_crypt = &mut [0; 1536];
	stream.crypt(buf_crypt);

	assert!(buf_read == buf_crypt);
}

#[test]
fn check_seek_to_end_and_read() {
	let mut stream = ChaCha20::new([0; 32], [0; 12]);

	stream.seek(SeekFrom::End(-7)).unwrap();

	assert!(stream.read(&mut [0; 64]).unwrap() == 7);
}
