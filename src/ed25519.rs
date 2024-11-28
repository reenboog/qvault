use rand::rngs::OsRng;
use rand::RngCore;
use serde::{self, Deserialize, Serialize};

use crate::base64_blobs::{deserialize_array_base64, serialize_array_base64};
use crate::{
	key_pair::{KeyPair, KeyPairSize},
	private_key::PrivateKey,
	public_key::PublicKey,
};

pub const SIG_SIZE: usize = ed25519_dalek::SIGNATURE_LENGTH;

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
	#[serde(
		serialize_with = "serialize_array_base64::<_, SIG_SIZE>",
		deserialize_with = "deserialize_array_base64::<_, SIG_SIZE>"
	)]
	bytes: [u8; Self::SIZE],
}

impl Signature {
	const SIZE: usize = SIG_SIZE;

	pub fn new(bytes: [u8; Self::SIZE]) -> Self {
		Self { bytes }
	}

	pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
		&self.bytes
	}
}

impl TryFrom<Vec<u8>> for Signature {
	type Error = std::array::TryFromSliceError;

	fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
		Ok(Self::new(value.as_slice().try_into()?))
	}
}

#[derive(Debug, PartialEq)]
pub struct KeyTypeEd25519;

impl KeyPairSize for KeyTypeEd25519 {
	const PRIV: usize = ed25519_dalek::SECRET_KEY_LENGTH;
	const PUB: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;
}

pub type PrivateKeyEd25519 = PrivateKey<KeyTypeEd25519, { KeyTypeEd25519::PRIV }>;
pub type PublicKeyEd25519 = PublicKey<KeyTypeEd25519, { KeyTypeEd25519::PUB }>;
pub type KeyPairEd25519 =
	KeyPair<KeyTypeEd25519, { KeyTypeEd25519::PRIV }, { KeyTypeEd25519::PUB }>;

impl KeyPairEd25519 {
	pub fn generate() -> Self {
		let private = PrivateKeyEd25519::generate();
		let signing_key = ed25519_dalek::SigningKey::from_bytes(private.as_bytes());
		let public = PublicKeyEd25519::from(signing_key.verifying_key().as_bytes());

		Self::new(private, public)
	}
}

impl PrivateKeyEd25519 {
	pub fn generate() -> Self {
		let mut key = [0u8; KeyTypeEd25519::PRIV];
		OsRng.fill_bytes(&mut key);

		Self::from(&key)
	}

	pub fn sign(&self, msg: &[u8]) -> Signature {
		use ed25519_dalek::Signer;

		let signing_key = ed25519_dalek::SigningKey::from_bytes(self.as_bytes());
		let signature = signing_key.sign(&msg);

		Signature::new(signature.into())
	}
}

impl From<&PrivateKeyEd25519> for ed25519_dalek::SecretKey {
	fn from(key: &PrivateKeyEd25519) -> Self {
		key.as_bytes().clone()
	}
}

impl TryFrom<&PublicKeyEd25519> for ed25519_dalek::VerifyingKey {
	type Error = ed25519_dalek::SignatureError;

	fn try_from(key: &PublicKeyEd25519) -> Result<ed25519_dalek::VerifyingKey, Self::Error> {
		ed25519_dalek::VerifyingKey::from_bytes(key.as_bytes())
	}
}

impl PublicKeyEd25519 {
	pub fn verify(&self, msg: &[u8], signature: &Signature) -> bool {
		use ed25519_dalek::Verifier;

		if let Ok(public) = ed25519_dalek::VerifyingKey::from_bytes(self.as_bytes()) {
			public
				.verify(
					msg,
					&ed25519_dalek::Signature::from_bytes(signature.as_bytes()),
				)
				.is_ok()
		} else {
			false
		}
	}
}

#[cfg(test)]
mod tests {
	use super::{KeyPairEd25519, PrivateKeyEd25519, PublicKeyEd25519, Signature};

	#[test]
	fn test_rfc8032_vectors() {
		let public = b"\xfc\x51\xcd\x8e\x62\x18\xa1\xa3\x8d\xa4\x7e\xd0\x02\x30\xf0\x58\x08\x16\xed\x13\xba\x33\x03\xac\x5d\xeb\x91\x15\x48\x90\x80\x25";
		let msg = b"\xaf\x82";
		let signature = b"\x62\x91\xd6\x57\xde\xec\x24\x02\x48\x27\xe6\x9c\x3a\xbe\x01\xa3\x0c\xe5\x48\xa2\x84\x74\x3a\x44\x5e\x36\x80\xd7\xdb\x5a\xc3\xac\x18\xff\x9b\x53\x8d\x16\xf2\x90\xae\x67\xf7\x60\x98\x4d\xc6\x59\x4a\x7c\x15\xe9\x71\x6e\xd2\x8d\xc0\x27\xbe\xce\xea\x1e\xc4\x0a";

		assert!(PublicKeyEd25519::new(public.to_owned())
			.verify(msg, &Signature::new(signature.to_owned())));
	}

	#[test]
	fn test_signature_as_bytes() {
		let private = b"\xc5\xaa\x8d\xf4\x3f\x9f\x83\x7b\xed\xb7\x44\x2f\x31\xdc\xb7\xb1\x66\xd3\x85\x35\x07\x6f\x09\x4b\x85\xce\x3a\x2e\x0b\x44\x58\xf7";
		let msg = b"\xaf\x82";
		let signature = b"\x62\x91\xd6\x57\xde\xec\x24\x02\x48\x27\xe6\x9c\x3a\xbe\x01\xa3\x0c\xe5\x48\xa2\x84\x74\x3a\x44\x5e\x36\x80\xd7\xdb\x5a\xc3\xac\x18\xff\x9b\x53\x8d\x16\xf2\x90\xae\x67\xf7\x60\x98\x4d\xc6\x59\x4a\x7c\x15\xe9\x71\x6e\xd2\x8d\xc0\x27\xbe\xce\xea\x1e\xc4\x0a";

		assert_eq!(
			PrivateKeyEd25519::new(private.to_owned())
				.sign(msg)
				.as_bytes(),
			signature
		);
	}

	#[test]
	fn test_sign_verify() {
		let kp = KeyPairEd25519::generate();
		let msg = b"123456";
		let sig = kp.private_key().sign(msg);

		assert!(kp.public_key().verify(msg, &sig));
	}

	#[test]
	fn test_verification_fails_with_wrong_key() {
		let kp1 = KeyPairEd25519::generate();
		let kp2 = KeyPairEd25519::generate();
		let msg = b"123456";
		let sig1 = kp1.private_key().sign(msg);
		let sig2 = kp2.private_key().sign(msg);

		assert!(kp1.public_key().verify(msg, &sig1));
		assert!(kp2.public_key().verify(msg, &sig2));
		assert!(!kp1.public_key().verify(msg, &sig2));
		assert!(!kp2.public_key().verify(msg, &sig1));
	}
}
