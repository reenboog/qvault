use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(PartialEq, Debug, Clone)]
pub struct Key([u8; Self::SIZE]);

impl Key {
	pub const SIZE: usize = 32;

	pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
		&self.0
	}

	pub fn new(bytes: [u8; Self::SIZE]) -> Self {
		Self(bytes)
	}
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Digest(pub [u8; Self::SIZE]);

impl Digest {
	pub const SIZE: usize = 32;

	pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
		&self.0
	}
}

impl From<Digest> for Key {
	fn from(digest: Digest) -> Self {
		Self(digest.0)
	}
}

impl From<&[u8; Key::SIZE]> for Key {
	fn from(slice: &[u8; Key::SIZE]) -> Self {
		Self(*slice)
	}
}

impl From<&[u8; Digest::SIZE]> for Digest {
	fn from(slice: &[u8; Digest::SIZE]) -> Self {
		Self(*slice)
	}
}

impl TryFrom<Vec<u8>> for Digest {
	type Error = std::array::TryFromSliceError;

	fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
		let slice: [u8; Self::SIZE] = value.as_slice().try_into()?;

		Ok(Self(slice))
	}
}

impl TryFrom<Vec<u8>> for Key {
	type Error = std::array::TryFromSliceError;

	fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
		let slice: [u8; Self::SIZE] = value.as_slice().try_into()?;

		Ok(Self::new(slice))
	}
}

pub fn digest(key: &Key, msg: &[u8]) -> Digest {
	let mut mac = HmacSha256::new_from_slice(&key.0).unwrap();

	mac.update(msg);

	Digest(mac.finalize().into_bytes().into())
}

pub fn verify(msg: &[u8], key: &Key, hash: &Digest) -> bool {
	let mut mac = HmacSha256::new_from_slice(&key.0).unwrap();

	mac.update(msg);

	mac.verify_slice(&hash.0).is_ok()
}

#[cfg(test)]
mod tests {
	use super::*;

	const KEY_SIZE: usize = Key::SIZE;
	const MAC_SIZE: usize = Digest::SIZE;

	#[test]
	fn test_non_zeroes() {
		let key = Key([123u8; KEY_SIZE]);
		let msg = b"abcdef";
		let digest = digest(&key, msg);

		assert_ne!(digest.0, [0u8; MAC_SIZE]);
	}

	#[test]
	fn test_openssl_vecs() {
		// verified by `echo -n $VALUE-TO-DIGEST | openssl dgst -sha256 -hmac $KEY -binary | xxd -p`
		let pt = b"value-to-digest";
		let key = b"12345678901234567890123456789012";
		let expected = b"\xd0\xbd\xa9\xa1\xfd\xd4\xed\xa6\xa5\x46\x38\xb7\x73\x8e\x38\x05\xeb\x26\x55\x97\xa0\xcc\x0b\xd0\xd7\xd3\x19\x4b\x20\x42\x70\xb5";
		let key = Key(key.to_owned());
		let mac = digest(&key, pt);

		assert_eq!(mac.as_bytes(), expected);
	}

	#[test]
	fn test_digest_same_inut_with_different_keys() {
		let key1 = Key([123u8; KEY_SIZE]);
		let key2 = Key([42u8; KEY_SIZE]);
		let msg = b"abcdef";

		let d1 = digest(&key1, msg);
		let d2 = digest(&key2, msg);

		assert_ne!(d1.0, d2.0);
	}

	#[test]
	fn test_digest_different_input_with_same_key() {
		let key = Key([123u8; KEY_SIZE]);
		let msg1 = b"abcdef";
		let msg2 = b"12345";

		let d1 = digest(&key, msg1);
		let d2 = digest(&key, msg2);

		assert_ne!(d1.0, d2.0);
	}

	#[test]
	fn test_same_digest_for_same_inputs_and_keys() {
		let key = Key([123u8; KEY_SIZE]);
		let msg = b"abcdef";
		let d1 = digest(&key, msg);
		let d2 = digest(&key, msg);

		assert_eq!(d1.0, d2.0);
	}

	#[test]
	fn test_verify() {
		let key = Key([2u8; KEY_SIZE]);
		let msg = b"hi there";
		let digest = digest(&key, msg);

		assert!(verify(msg, &key, &digest));
	}
}
