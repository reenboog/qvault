use crate::hmac::{self, Digest};

pub struct Hkdf {
	prk: Digest,
}

impl Hkdf {
	const EMPTY_KEY: [u8; hmac::Key::SIZE] = [0u8; hmac::Key::SIZE];

	pub fn new(prk: Digest) -> Self {
		Self { prk }
	}

	pub fn from_ikm(ikm: &[u8]) -> Self {
		Self::from_ikm_keyed(ikm, &Self::EMPTY_KEY)
	}

	pub fn from_ikm_keyed(ikm: &[u8], key: &[u8; hmac::Key::SIZE]) -> Self {
		Self::new(hmac::digest(&hmac::Key::new(*key), ikm))
	}

	// TODO: introduce a new type for expanded?, clarify its size; or may be just a const or a combined type, ie KeyMac?
	pub fn expand_no_info<const LEN: usize>(&self) -> [u8; LEN] {
		self.expand(b"")
	}

	pub fn expand<const LEN: usize>(&self, info: &[u8]) -> [u8; LEN] {
		assert!(LEN > 1); // TODO: would be nice to introduce a compile time type with checks: by making Hkdf accept LEN instead of expand?

		let n = (LEN - 1) / Digest::SIZE + 1;

		let mut res = Vec::<u8>::new();
		let mut prev = Vec::<u8>::new();

		for i in 1..n + 1 {
			let mut input = prev;

			input.extend(info);
			input.push(i as u8);

			prev = hmac::digest(&self.prk.into(), &input).as_bytes().to_vec();
			res.extend(&prev);
		}

		res[..LEN].try_into().unwrap()
	}
}

#[cfg(test)]
mod tests {
	use crate::{hkdf::Hkdf, hmac::Digest};

	// [1u8; 32] hmac-ed with EMPTY_KEY
	const DIGEST: &[u8; 32] = b"\x80\xa0\x9d\xe3\xbf\xe3\x0d\xa9\x01\x16\xe5\x88\xad\xe2\xf8\x12\xd4\x9b\x55\x62\x5b\xe8\xb4\xab\xbf\xf7\x75\xfa\x5a\x5a\x74\xe9";
	// DIGEST hkdf-ed up to 80 with b"SecureMessenger"
	const RES: &[u8; 80] = b"\x69\xef\xc1\x01\x77\xa9\x2d\x9f\x65\x47\x82\x64\x0d\xbd\x07\xa4\xf4\x2a\x8d\xe1\x6c\x99\x28\x2d\x46\x4c\xa6\x8b\x7e\x5e\x69\x4a\x57\x2c\x91\x39\xb6\x0b\x8e\x5d\xb1\xf1\xb0\x01\xe9\x98\x7a\xdc\xd7\xef\x5a\xde\x7f\x38\x5a\x84\x43\xfb\x44\xad\x99\x08\x9a\x88\x40\x4c\x5d\xf2\x3c\x80\x14\xe4\x0a\xa1\x65\x72\x6c\x37\x94\x0e";

	#[test]
	fn test_not_zeroes() {
		let digest = Digest(DIGEST.to_owned());
		let res = Hkdf::new(digest).expand::<80>(b"SecureMessenger");

		assert_ne!(res, [0u8; 80]);
	}

	#[test]
	fn test_extract_from_ikm() {
		let ikm = [1u8; 32];
		let key = Hkdf::EMPTY_KEY.to_owned();

		let res = Hkdf::from_ikm_keyed(&ikm, &key).expand::<80>(b"SecureMessenger");

		assert_eq!(res, RES.to_owned());
	}

	#[test]
	fn test_expand() {
		let digest = Digest(DIGEST.to_owned());
		let res = Hkdf::new(digest).expand::<80>(b"SecureMessenger");

		assert_eq!(res, RES.to_owned());
	}

	#[test]
	fn test_expand_to_non_block_size() {
		let digest = Digest(DIGEST.to_owned());
		let res = Hkdf::new(digest).expand(b"SecureMessenger");

		assert_eq!(res, b"\x69\xef".to_owned());
	}

	#[test]
	fn test_expand_same_info_wrong_digest() {
		let digest = Digest(b"\x05\x25\x9b\x85\xc5\x2d\x50\x60\x14\xa9\xba\x39\xc4\x13\x94\x72\xe2\x7f\x97\x88\x5d\xc4\x00\x70\xfb\xda\x54\x3b\x74\xb3\xda\x61".to_owned());
		let res = Hkdf::new(digest).expand::<80>(b"SecureMessenger");

		assert_ne!(res, RES.to_owned());
	}

	#[test]
	fn test_expand_same_digest_wrong_info() {
		let digest = Digest(DIGEST.to_owned());
		let res = Hkdf::new(digest).expand::<80>(b"NotSecureMessenger");

		assert_ne!(res, RES.to_owned());
	}
}
