use crate::base64_blobs::{deserialize_array_base64, serialize_array_base64};
use aes_gcm::{
	aead::{generic_array::GenericArray, Aead, NewAead},
	Aes256Gcm,
};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::hkdf;

pub const KEY_SIZE: usize = 32;
pub const IV_SIZE: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Key {
	#[serde(
		serialize_with = "serialize_array_base64::<_, KEY_SIZE>",
		deserialize_with = "deserialize_array_base64::<_, KEY_SIZE>"
	)]
	pub bytes: [u8; Self::SIZE],
}

impl Key {
	pub const SIZE: usize = KEY_SIZE;

	pub fn generate() -> Self {
		let mut key = [0u8; Self::SIZE];
		OsRng.fill_bytes(&mut key);
		Self { bytes: key }
	}

	pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
		&self.bytes
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Iv {
	#[serde(
		serialize_with = "serialize_array_base64::<_, {IV_SIZE}>",
		deserialize_with = "deserialize_array_base64::<_, IV_SIZE>"
	)]
	pub bytes: [u8; Self::SIZE],
}

impl Iv {
	pub const SIZE: usize = IV_SIZE;

	pub fn generate() -> Self {
		let mut iv = [0u8; Self::SIZE];
		OsRng.fill_bytes(&mut iv);
		Self { bytes: iv }
	}

	pub fn as_bytes(&self) -> &[u8; Self::SIZE] {
		&self.bytes
	}
}

#[derive(Debug, PartialEq)]
pub enum Error {
	WrongKeyMaterial,
	WrongKeyIvSize,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Aes {
	pub key: Key,
	pub iv: Iv,
}

impl Aes {
	pub fn new() -> Self {
		Self::new_with_key_iv(Key::generate(), Iv::generate())
	}

	pub fn new_with_key(key: Key) -> Self {
		Self::new_with_key_iv(key, Iv::generate())
	}

	pub fn new_with_key_iv(key: Key, iv: Iv) -> Self {
		Self { key, iv }
	}

	pub async fn encrypt_async(&self, pt: &[u8]) -> Vec<u8> {
		self.encrypt(pt)
	}

	pub async fn decrypt_async(&self, ct: &[u8]) -> Result<Vec<u8>, Error> {
		self.decrypt(ct)
	}

	pub fn encrypt(&self, pt: &[u8]) -> Vec<u8> {
		let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.key.bytes));
		let nonce = GenericArray::from_slice(&self.iv.bytes);
		cipher.encrypt(nonce, pt).unwrap()
	}

	pub fn encrypt_serializable<T>(&self, pt: T) -> Vec<u8>
	where
		T: Serialize,
	{
		let serialized = serde_json::to_vec(&pt).unwrap();

		self.encrypt(&serialized)
	}

	pub fn decrypt(&self, ct: &[u8]) -> Result<Vec<u8>, Error> {
		let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.key.bytes));
		let nonce = GenericArray::from_slice(&self.iv.bytes);
		cipher
			.decrypt(nonce, ct)
			.map_err(|_| Error::WrongKeyMaterial)
	}

	fn key_for_chunk_idx(&self, idx: u32) -> Self {
		let chunk_key = hkdf::Hkdf::from_ikm(&self.as_bytes())
			.expand::<{ Key::SIZE + Iv::SIZE }>(&idx.to_be_bytes());

		Aes::from(&chunk_key)
	}

	pub fn chunk_encrypt(&self, idx: u32, pt: &[u8]) -> Vec<u8> {
		let aes = self.key_for_chunk_idx(idx);

		aes.encrypt(pt)
	}

	pub async fn chunk_encrypt_async(&self, idx: u32, pt: &[u8]) -> Vec<u8> {
		let aes = self.key_for_chunk_idx(idx);

		aes.encrypt_async(pt).await
	}

	pub fn chunk_decrypt(&self, idx: u32, ct: &[u8]) -> Result<Vec<u8>, Error> {
		let aes = self.key_for_chunk_idx(idx);

		aes.decrypt(ct)
	}

	pub async fn chunk_decrypt_async(&self, idx: u32, ct: &[u8]) -> Result<Vec<u8>, Error> {
		let aes = self.key_for_chunk_idx(idx);

		aes.decrypt_async(ct).await
	}

	pub fn as_bytes(&self) -> [u8; Key::SIZE + Iv::SIZE] {
		[
			self.key.as_bytes().as_slice(),
			self.iv.as_bytes().as_slice(),
		]
		.concat()
		.try_into()
		.unwrap()
	}
}

impl TryFrom<&[u8]> for Aes {
	type Error = Error;

	fn try_from(val: &[u8]) -> Result<Self, Self::Error> {
		if val.len() != Key::SIZE + Iv::SIZE {
			Err(Error::WrongKeyIvSize)
		} else {
			Ok(Self::new_with_key_iv(
				Key {
					bytes: val[..Key::SIZE].try_into().unwrap(),
				},
				Iv {
					bytes: val[Key::SIZE..].try_into().unwrap(),
				},
			))
		}
	}
}

impl From<&[u8; Key::SIZE + Iv::SIZE]> for Aes {
	fn from(val: &[u8; Key::SIZE + Iv::SIZE]) -> Self {
		Self::new_with_key_iv(
			Key {
				bytes: val[..Key::SIZE].try_into().unwrap(),
			},
			Iv {
				bytes: val[Key::SIZE..].try_into().unwrap(),
			},
		)
	}
}

#[cfg(test)]
mod tests {
	use rand::{rngs::OsRng, RngCore};

	use super::{Aes, Error, Iv, Key};

	#[test]
	fn test_encrypt_decrypt() {
		let aes = Aes::new();
		let ref_pt = b"abcdefghijklmnopqrstuvwxyz";

		let ct = aes.encrypt(ref_pt);
		let pt = aes.decrypt(&ct).unwrap();

		assert_eq!(pt, ref_pt.to_vec());
	}

	#[test]
	fn test_encrypt_empty() {
		let aes = Aes::new();
		let ct = aes.encrypt(b"");
		let pt = aes.decrypt(&ct).unwrap();

		assert_eq!(pt, b"");
	}

	#[test]
	fn test_decrypt_fails_with_wrong_key_iv() {
		let ref_aes = Aes::new();
		let ref_pt = b"abcdefghijklmnopqrstuvwxyz";

		let ct = ref_aes.encrypt(ref_pt);
		let pt = ref_aes.decrypt(&ct).unwrap();

		assert_eq!(pt, ref_pt);

		let mut wrong_key_aes = ref_aes.clone();
		wrong_key_aes.key = Key::generate();

		assert_eq!(wrong_key_aes.decrypt(&ct), Err(Error::WrongKeyMaterial));

		let mut wrong_iv_aes = ref_aes.clone();
		wrong_iv_aes.iv = Iv::generate();

		assert_eq!(wrong_iv_aes.decrypt(&ct), Err(Error::WrongKeyMaterial));
	}

	#[test]
	fn test_new() {
		let aes = Aes::new_with_key_iv(
			Key {
				bytes: [12u8; Key::SIZE],
			},
			Iv {
				bytes: [34u8; Iv::SIZE],
			},
		);

		let ref_pt = b"abcdefghijklmnopqrstuvwxyz";

		let ct = aes.encrypt(ref_pt);
		let pt = aes.decrypt(&ct).unwrap();

		assert_eq!(pt, ref_pt.to_vec());
	}

	#[test]
	fn test_try_from() {
		let aes = Aes::new();
		let as_bytes = aes.as_bytes();

		assert_eq!(Ok(aes), Aes::try_from(as_bytes.as_slice()));
		assert_eq!(
			Err(Error::WrongKeyIvSize),
			Aes::try_from(vec![1, 2, 3].as_slice())
		);
	}

	#[test]
	fn test_chunk_encrypt_decrypt() {
		let aes = Aes::new();
		// just an arbitrary size
		let mut msg = [0u8; 193];

		OsRng.fill_bytes(&mut msg);

		let mut ct = Vec::new();
		let mut pt = Vec::new();
		let chunks = 10;
		let pt_chunk_len = msg.len() / chunks;

		for i in 0..chunks {
			let start = i * pt_chunk_len;
			let end = if i == chunks - 1 {
				msg.len()
			} else {
				(i + 1) * pt_chunk_len
			};
			let chunk = &msg[start..end];
			let encrypted_chunk = aes.chunk_encrypt(i as u32, chunk);
			let decrypted_chunk = aes.chunk_decrypt(i as u32, &encrypted_chunk).unwrap();

			assert_eq!(chunk, decrypted_chunk);

			ct.extend(encrypted_chunk.into_iter());
		}

		// adjust to aes gcm's auth tag
		let ct_chunk_len = pt_chunk_len + 16;
		for i in 0..chunks {
			let start = i * ct_chunk_len;
			let end = if i == chunks - 1 {
				ct.len()
			} else {
				(i + 1) * ct_chunk_len
			};
			let chunk = aes.chunk_decrypt(i as u32, &ct[start..end]).unwrap();

			pt.extend(chunk.into_iter());
		}

		assert_eq!(msg.to_vec(), pt);
	}
}
