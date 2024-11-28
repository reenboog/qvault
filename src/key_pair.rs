use crate::{id::Uid, private_key::PrivateKey, public_key::PublicKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound(
	serialize = "PrivateKey<T, PRIV_SIZE>: Serialize, PublicKey<T, PUB_SIZE>: Serialize",
	deserialize = "PrivateKey<T, PRIV_SIZE>: Deserialize<'de>, PublicKey<T, PUB_SIZE>: Deserialize<'de>"
))]
pub struct KeyPair<T, const PRIV_SIZE: usize, const PUB_SIZE: usize> {
	pub(crate) private: PrivateKey<T, PRIV_SIZE>,
	pub(crate) public: PublicKey<T, PUB_SIZE>,
}

impl<T, const PRIV_SIZE: usize, const PUB_SIZE: usize> KeyPair<T, PRIV_SIZE, PUB_SIZE> {
	pub fn new(private: PrivateKey<T, PRIV_SIZE>, public: PublicKey<T, PUB_SIZE>) -> Self {
		Self { private, public }
	}

	pub fn public_key(&self) -> &PublicKey<T, PUB_SIZE> {
		&self.public
	}

	pub fn private_key(&self) -> &PrivateKey<T, PRIV_SIZE> {
		&self.private
	}

	pub fn id(&self) -> Uid {
		self.public_key().id()
	}
}

impl<T, const PRIV_SIZE: usize, const PUB_SIZE: usize> Clone for KeyPair<T, PRIV_SIZE, PUB_SIZE> {
	fn clone(&self) -> Self {
		Self::new(self.private.clone(), self.public.clone())
	}
}

pub trait KeyPairSize {
	const PRIV: usize;
	const PUB: usize;
}

#[cfg(test)]
mod tests {
	use super::*;

	#[derive(Debug, PartialEq)]
	struct TestKeyType;

	#[test]
	fn test_new() {
		let private = PrivateKey::<TestKeyType, 2>::new(b"12".to_owned());
		let public = PublicKey::<TestKeyType, 4>::new(b"1234".to_owned());

		let _ = KeyPair::<TestKeyType, 2, 4>::new(private, public);

		// this won't compile because of different types:
		// let bad_key = PublicKey::<OtherType, 4>::new(b"1234".to_owned());
		// let kp = KeyPair::<TestKeyType, 2, 4>::new(private, bad_key);

		// this won't compile because of different sizes:
		// let bad_key = PublicKey::<TestKeyType, 10>::new(b"0123456789".to_owned());
		// let kp = KeyPair::<TestKeyType, 2, 4>::new(private, bad_key);
	}

	#[test]
	fn test_serialize_deserialize() {
		let private = PrivateKey::<TestKeyType, 10>::new(b"1234567890".to_owned());
		let public = PublicKey::<TestKeyType, 4>::new(b"9876".to_owned());
		let kp = KeyPair::<TestKeyType, 10, 4>::new(private, public);

		let serialized = serde_json::to_string(&kp).unwrap();
		let deserialized = serde_json::from_str(&serialized).unwrap();

		assert_eq!(kp, deserialized);
	}
}
