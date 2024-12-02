use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::{
	aes_gcm,
	base64_blobs::{deserialize_vec_base64, serialize_vec_base64},
	hkdf,
	key_pair::{KeyPair, KeyPairSize},
	private_key::{PrivateKey, SharedKey},
	public_key::PublicKey,
};

#[derive(Debug, PartialEq)]
pub struct KeyTypeX448;

impl KeyPairSize for KeyTypeX448 {
	const PRIV: usize = 56;
	const PUB: usize = 56;
}

impl KeyTypeX448 {
	const SHARED: usize = 56;
}

pub type PrivateKeyX448 = PrivateKey<KeyTypeX448, { KeyTypeX448::PRIV }>;
pub type PublicKeyX448 = PublicKey<KeyTypeX448, { KeyTypeX448::PUB }>;
pub type KeyPairX448 = KeyPair<KeyTypeX448, { KeyTypeX448::PRIV }, { KeyTypeX448::PUB }>;
pub type SharedKeyX448 = SharedKey<KeyTypeX448, { KeyTypeX448::SHARED }>;

#[derive(Debug, PartialEq)]
pub enum Error {
	BadKey,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Encrypted {
	// encrypted message
	#[serde(
		serialize_with = "serialize_vec_base64",
		deserialize_with = "deserialize_vec_base64"
	)]
	pub ct: Vec<u8>,
	// an ephemeral key, dh-ed with an identity pub key
	pub eph_x448: PublicKeyX448,
}

fn aes_from_dh_keys(sk: &PrivateKeyX448, pk: &PublicKeyX448) -> aes_gcm::Aes {
	let shared = dh_exchange(sk, pk);
	let key_iv = hkdf::Hkdf::from_ikm(shared.as_bytes())
		.expand_no_info::<{ aes_gcm::Key::SIZE + aes_gcm::Iv::SIZE }>();

	aes_gcm::Aes::from(&key_iv)
}

impl PrivateKeyX448 {
	pub fn generate() -> Self {
		use x448::Secret;

		let mut bytes = [0u8; KeyTypeX448::PRIV];
		let mut csprng = rand::thread_rng();

		csprng.fill_bytes(&mut bytes);

		let secret = Secret::from(bytes);

		secret.as_bytes().into()
	}

	pub fn decrypt(&self, encrypted: &Encrypted) -> Result<Vec<u8>, Error> {
		let aes = aes_from_dh_keys(&self, &encrypted.eph_x448);
		let pt = aes.decrypt(&encrypted.ct).map_err(|_| Error::BadKey)?;

		Ok(pt)
	}
}

impl PublicKeyX448 {
	pub fn from_private(key: &PrivateKeyX448) -> Self {
		use x448::{PublicKey, Secret};

		let secret = Secret::from(key);
		let public = PublicKey::from(&secret);

		public.as_bytes().into()
	}

	pub fn encrypt_serialized(&self, pt: &[u8]) -> Encrypted {
		let kp = KeyPairX448::generate();
		let aes = aes_from_dh_keys(kp.private_key(), &self);
		let ct = aes.encrypt(pt);

		Encrypted {
			ct,
			eph_x448: kp.public_key().clone(),
		}
	}

	pub fn encrypt<T>(&self, pt: T) -> Encrypted
	where
		T: Serialize,
	{
		let serialized = serde_json::to_vec(&pt).unwrap();

		self.encrypt_serialized(&serialized)
	}
}

// internal use only
impl From<&PrivateKeyX448> for x448::Secret {
	fn from(key: &PrivateKeyX448) -> Self {
		// TODO: how about low order points?
		Self::from_bytes(key.as_bytes()).unwrap()
	}
}

// internal use only
impl From<&PublicKeyX448> for x448::PublicKey {
	fn from(key: &PublicKeyX448) -> Self {
		// TODO: how about low order points?
		Self::from_bytes(key.as_bytes()).unwrap()
	}
}

impl KeyPairX448 {
	pub fn generate() -> Self {
		let private = PrivateKeyX448::generate();
		let public = PublicKeyX448::from_private(&private);

		Self::new(private, public)
	}
}

pub fn dh_exchange(private: &PrivateKeyX448, public: &PublicKeyX448) -> SharedKeyX448 {
	use x448::{PublicKey, Secret};

	let private = Secret::from(private);
	let public = PublicKey::from(public);
	let shared = private.as_diffie_hellman(&public).unwrap();

	SharedKeyX448::new(*shared.as_bytes())
}

#[cfg(test)]
mod tests {
	use serde::{Deserialize, Serialize};

	use super::{dh_exchange, KeyPairX448, KeyTypeX448, PrivateKeyX448, PublicKeyX448};
	use crate::key_pair::KeyPairSize;

	#[test]
	fn test_dh_rfc7748_vectors() {
		let alice = b"\x9a\x8f\x49\x25\xd1\x51\x9f\x57\x75\xcf\x46\xb0\x4b\x58\x00\xd4\xee\x9e\xe8\xba\xe8\xbc\x55\x65\xd4\x98\xc2\x8d\xd9\xc9\xba\xf5\x74\xa9\x41\x97\x44\x89\x73\x91\x00\x63\x82\xa6\xf1\x27\xab\x1d\x9a\xc2\xd8\xc0\xa5\x98\x72\x6b";
		let bob = b"\x3e\xb7\xa8\x29\xb0\xcd\x20\xf5\xbc\xfc\x0b\x59\x9b\x6f\xec\xcf\x6d\xa4\x62\x71\x07\xbd\xb0\xd4\xf3\x45\xb4\x30\x27\xd8\xb9\x72\xfc\x3e\x34\xfb\x42\x32\xa1\x3c\xa7\x06\xdc\xb5\x7a\xec\x3d\xae\x07\xbd\xc1\xc6\x7b\xf3\x36\x09";
		let shared_ref = b"\x07\xff\xf4\x18\x1a\xc6\xcc\x95\xec\x1c\x16\xa9\x4a\x0f\x74\xd1\x2d\xa2\x32\xce\x40\xa7\x75\x52\x28\x1d\x28\x2b\xb6\x0c\x0b\x56\xfd\x24\x64\xc3\x35\x54\x39\x36\x52\x1c\x24\x40\x30\x85\xd5\x9a\x44\x9a\x50\x37\x51\x4a\x87\x9d";

		let alice = PrivateKeyX448::new(alice.to_owned());
		let bob = PublicKeyX448::new(bob.to_owned());
		let shared = dh_exchange(&alice, &bob);

		assert_eq!(shared.as_bytes(), shared_ref);
	}

	#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
	struct Msg {
		data: Vec<u8>,
	}

	#[test]
	fn test_encrypt_decrypt_serialized() {
		let kp = KeyPairX448::generate();
		let pt = b"hello there";
		let ct = kp.public_key().encrypt_serialized(pt);
		let decrypted = kp.private_key().decrypt(&ct);

		assert_eq!(decrypted, Ok(pt.to_vec()));
	}

	#[test]
	fn test_encrypt_decrypt() {
		let kp = KeyPairX448::generate();
		let pt = Msg {
			data: vec![117u8; 100],
		};
		let ct = kp.public_key().encrypt(pt.clone());
		let decrypted = kp.private_key().decrypt(&ct).unwrap();
		let deserialized: Msg = serde_json::from_slice(&decrypted).unwrap();

		assert_eq!(deserialized, pt);
	}

	#[test]
	fn test_public_from_private_rfc7748_vec() {
		let private = PrivateKeyX448::new(b"\x9a\x8f\x49\x25\xd1\x51\x9f\x57\x75\xcf\x46\xb0\x4b\x58\x00\xd4\xee\x9e\xe8\xba\xe8\xbc\x55\x65\xd4\x98\xc2\x8d\xd9\xc9\xba\xf5\x74\xa9\x41\x97\x44\x89\x73\x91\x00\x63\x82\xa6\xf1\x27\xab\x1d\x9a\xc2\xd8\xc0\xa5\x98\x72\x6b".to_owned());
		let public = PublicKeyX448::from_private(&private);

		assert_eq!(public.as_bytes().to_owned(), b"\x9b\x08\xf7\xcc\x31\xb7\xe3\xe6\x7d\x22\xd5\xae\xa1\x21\x07\x4a\x27\x3b\xd2\xb8\x3d\xe0\x9c\x63\xfa\xa7\x3d\x2c\x22\xc5\xd9\xbb\xc8\x36\x64\x72\x41\xd9\x53\xd4\x0c\x5b\x12\xda\x88\x12\x0d\x53\x17\x7f\x80\xe5\x32\xc4\x1f\xa0".to_owned());
	}

	#[test]
	fn test_gen_private_not_zeroes() {
		let key = PrivateKeyX448::generate();

		assert_ne!(key.as_bytes().to_owned(), [0u8; KeyTypeX448::PRIV])
	}

	#[test]
	fn test_gen_keypair_non_zeroes() {
		let kp = KeyPairX448::generate();

		assert_ne!(
			kp.private_key().as_bytes().to_owned(),
			[0u8; KeyTypeX448::PRIV]
		);
		assert_ne!(
			kp.public_key().as_bytes().to_owned(),
			[0u8; KeyTypeX448::PUB]
		);
	}

	#[test]
	fn test_dh_exchange() {
		let alice_kp = KeyPairX448::generate();
		let bob_kp = KeyPairX448::generate();
		let dh_ab = dh_exchange(alice_kp.private_key(), bob_kp.public_key());
		let dh_ba = dh_exchange(bob_kp.private_key(), alice_kp.public_key());

		assert_ne!(dh_ab.as_bytes().to_owned(), [0u8; KeyTypeX448::SHARED]);
		assert_eq!(dh_ab, dh_ba);
	}
}
