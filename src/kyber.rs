use crate::{aes_gcm, hkdf};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::{
	key_pair::{KeyPair as KP, KeyPairSize},
	private_key::PrivateKey,
	public_key::PublicKey,
};

#[derive(Debug, PartialEq)]
pub enum Error {
	BadCt,
	WrongKey,
}

#[derive(Debug, PartialEq)]
pub struct KeyTypeKyber;

impl KeyPairSize for KeyTypeKyber {
	const PRIV: usize = pqc_kyber::KYBER_SECRETKEYBYTES;
	const PUB: usize = pqc_kyber::KYBER_PUBLICKEYBYTES;
}

impl KeyTypeKyber {
	const SHARED: usize = pqc_kyber::KYBER_SSBYTES;
	const CT: usize = pqc_kyber::KYBER_CIPHERTEXTBYTES;
}

pub type PrivateKeyKyber = PrivateKey<KeyTypeKyber, { KeyTypeKyber::PRIV }>;
pub type PublicKeyKyber = PublicKey<KeyTypeKyber, { KeyTypeKyber::PUB }>;
pub type KeyPairKyber = KP<KeyTypeKyber, { KeyTypeKyber::PRIV }, { KeyTypeKyber::PUB }>;
pub type SharedKeyKyber = PrivateKey<KeyTypeKyber, { KeyTypeKyber::SHARED }>;
pub type CiphertextKyber = PublicKey<KeyTypeKyber, { KeyTypeKyber::CT }>;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Encrypted {
	kyber_ct: CiphertextKyber,
	ct: Vec<u8>,
}

fn aes_from_shared_key(ss: &SharedKeyKyber) -> aes_gcm::Aes {
	let key_iv = hkdf::Hkdf::from_ikm(ss.as_bytes())
		.expand_no_info::<{ aes_gcm::Key::SIZE + aes_gcm::Iv::SIZE }>();

	aes_gcm::Aes::from(&key_iv)
}

impl PublicKeyKyber {
	fn encapsulate(&self) -> (CiphertextKyber, SharedKeyKyber) {
		let mut rng = OsRng;

		let (ciphertext, shared) = pqc_kyber::encapsulate(self.as_bytes(), &mut rng).unwrap();

		(
			CiphertextKyber::from(&ciphertext),
			SharedKeyKyber::from(&shared),
		)
	}

	pub fn encrypt_serialized(&self, pt: &[u8]) -> Encrypted {
		let (kyber_ct, ss) = self.encapsulate();
		let aes = aes_from_shared_key(&ss);
		let ct = aes.encrypt(pt);

		Encrypted { kyber_ct, ct }
	}

	pub fn encrypt<T>(&self, pt: T) -> Encrypted
	where
		T: Serialize,
	{
		let serialized = serde_json::to_vec(&pt).unwrap();

		self.encrypt_serialized(&serialized)
	}
}

impl PrivateKeyKyber {
	fn decapsulate(&self, ct: &[u8]) -> Result<SharedKeyKyber, Error> {
		let shared = pqc_kyber::decapsulate(ct, self.as_bytes()).map_err(|_| Error::BadCt)?;

		Ok(SharedKeyKyber::from(&shared))
	}

	pub fn decrypt(&self, ct: &Encrypted) -> Result<Vec<u8>, Error> {
		let ss = self.decapsulate(ct.kyber_ct.as_bytes())?;
		let aes = aes_from_shared_key(&ss);
		let pt = aes.decrypt(&ct.ct).map_err(|_| Error::WrongKey)?;

		Ok(pt)
	}
}

impl KeyPairKyber {
	pub fn generate() -> Self {
		let mut rng = OsRng;
		let pqc_kyber::Keypair { public, secret } = pqc_kyber::keypair(&mut rng).unwrap();

		Self {
			private: PrivateKeyKyber::from(&secret),
			public: PublicKeyKyber::from(&public),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::{CiphertextKyber, KeyPairKyber, PrivateKeyKyber, SharedKeyKyber};
	use serde::{Deserialize, Serialize};

	#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
	struct Msg {
		data: Vec<u8>,
	}

	#[test]
	fn test_encrypt_decrypt() {
		let kp = KeyPairKyber::generate();
		let pt = Msg {
			data: vec![117u8; 100],
		};
		let ct = kp.public_key().encrypt(pt.clone());
		let decrypted = kp.private_key().decrypt(&ct).unwrap();
		let deserialized: Msg = serde_json::from_slice(&decrypted).unwrap();

		assert_eq!(deserialized, pt);
	}

	#[test]
	fn test_encrypt_decrypt_serialized() {
		let kp = KeyPairKyber::generate();
		let pt = b"hey there";
		let ct = kp.public_key().encrypt_serialized(pt);
		let decrypted = kp.private_key().decrypt(&ct);

		assert_eq!(decrypted, Ok(pt.to_vec()));
	}
}
