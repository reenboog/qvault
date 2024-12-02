use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
	aes_gcm,
	base64_blobs::{deserialize_vec_base64, serialize_vec_base64},
	ed25519::{KeyPairEd25519, PrivateKeyEd25519, PublicKeyEd25519, Signature},
	hmac,
	id::Uid,
	kyber::{self, KeyPairKyber, PrivateKeyKyber, PublicKeyKyber},
	user::GOD_ID,
	x448::{self, KeyPairX448, PrivateKeyX448, PublicKeyX448},
};

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Identity {
	pub(crate) _priv: Private,
	pub(crate) _pub: Public,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Private {
	pub(crate) x448: PrivateKeyX448,
	pub(crate) ed25519: PrivateKeyEd25519,
	pub(crate) kyber: PrivateKeyKyber,
}

#[derive(Debug)]
pub enum Error {
	BadKey,
}

impl Private {
	pub fn decrypt(&self, ct: &Encrypted) -> Result<Vec<u8>, Error> {
		let ecc = self.kyber.decrypt(&ct.ecc_ct).map_err(|_| Error::BadKey)?;
		let ecc: x448::Encrypted = serde_json::from_slice(&ecc).map_err(|_| Error::BadKey)?;
		let aes = self.x448.decrypt(&ecc).map_err(|_| Error::BadKey)?;
		let aes: aes_gcm::Aes = serde_json::from_slice(&aes).map_err(|_| Error::BadKey)?;
		let pt = aes.decrypt(&ct.ct).map_err(|_| Error::BadKey)?;

		Ok(pt)
	}

	pub fn sign(&self, msg: &[u8]) -> Signature {
		self.ed25519.sign(msg)
	}
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Public {
	// created by by the inviting party (unless god)
	pub(crate) id: Uid,
	// can be used to encrypt messages to or verify signatures against
	pub(crate) x448: PublicKeyX448,
	pub(crate) ed25519: PublicKeyEd25519,
	pub(crate) kyber: PublicKeyKyber,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Encrypted {
	// layer 0: aes-encrypted data
	#[serde(
		serialize_with = "serialize_vec_base64",
		deserialize_with = "deserialize_vec_base64"
	)]
	ct: Vec<u8>,
	// layer 2: kyber encrypted ecc key (which in turn encrypts layer 1)
	ecc_ct: kyber::Encrypted,
}

impl Public {
	pub fn id(&self) -> Uid {
		// id::from_bytes(&[self.x448.as_bytes(), self.ed25519.as_bytes().as_slice()].concat())
		self.id
	}

	pub fn is_god(&self) -> bool {
		self.id == GOD_ID
	}

	pub fn encrypt_serialized(&self, pt: &[u8]) -> Encrypted {
		let aes = aes_gcm::Aes::new();
		let ct = aes.encrypt(pt);
		let aes_ct = self.x448.encrypt(&aes);
		let ecc_ct = self.kyber.encrypt(aes_ct.clone());

		Encrypted { ct, ecc_ct }
	}

	pub fn verify(&self, sig: &Signature, msg: &[u8]) -> bool {
		self.ed25519.verify(msg, sig)
	}

	pub fn hash(&self) -> hmac::Digest {
		let bytes = [
			self.x448.as_bytes().as_slice(),
			self.ed25519.as_bytes(),
			self.kyber.as_bytes(),
			&self.id().as_bytes(),
		]
		.concat();

		let sha = Sha256::digest(&bytes);

		hmac::Digest(sha.into())
	}
}

impl Public {
	pub fn encrypt<T>(&self, pt: T) -> Encrypted
	where
		T: Serialize,
	{
		let serialized = serde_json::to_vec(&pt).unwrap();

		self.encrypt_serialized(&serialized)
	}
}

impl Identity {
	pub fn id(&self) -> Uid {
		self._pub.id()
	}

	pub fn generate(id: Uid) -> Self {
		let KeyPairX448 {
			private: x448_priv,
			public: x448_pub,
		} = KeyPairX448::generate();
		let KeyPairEd25519 {
			private: ed25519_priv,
			public: ed25519_pub,
		} = KeyPairEd25519::generate();
		let KeyPairKyber {
			private: kyber_priv,
			public: kyber_pub,
		} = KeyPairKyber::generate();

		Self {
			_priv: Private {
				x448: x448_priv,
				ed25519: ed25519_priv,
				kyber: kyber_priv,
			},
			_pub: Public {
				id: id,
				x448: x448_pub,
				ed25519: ed25519_pub,
				kyber: kyber_pub,
			},
		}
	}

	pub(crate) fn public(&self) -> &Public {
		&self._pub
	}

	pub(crate) fn private(&self) -> &Private {
		&self._priv
	}
}

#[cfg(test)]
mod tests {
	use super::Identity;
	use crate::id::Uid;

	#[test]
	fn test_encrypt_decrypt() {
		let ident = Identity::generate(Uid::new(0));
		let msg = b"hi there";
		let encrypted = ident.public().encrypt_serialized(msg);
		let decrypted = ident.private().decrypt(&encrypted).unwrap();

		assert_eq!(decrypted, msg);
	}

	#[test]
	fn test_sign_verify() {
		let ident = Identity::generate(Uid::new(0));
		let msg = b"hi there";
		let sig = ident.private().sign(msg);

		assert!(ident.public().verify(&sig, msg));
	}

	#[test]
	fn test_serialize_deserialized() {
		let ident = Identity::generate(Uid::new(0));
		let serialized = serde_json::to_string(&ident).unwrap();
		let deserialized = serde_json::from_str(&serialized).unwrap();

		assert_eq!(ident, deserialized);
	}
}
