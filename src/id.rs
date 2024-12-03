use std::{fmt, str::FromStr};

use rand::{rngs::OsRng, Rng};
use serde::{
	de::{self, Visitor},
	Deserialize, Deserializer, Serialize, Serializer,
};
use sha2::{Digest, Sha256};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Uid(u64);

impl Uid {
	pub fn new(v: u64) -> Self {
		Self(v)
	}

	pub fn generate() -> Self {
		let mut rng = OsRng;
		Self(rng.gen())
	}

	pub fn from_bytes(bytes: &[u8]) -> Self {
		Self(u64::from_be_bytes(
			Sha256::digest(bytes).to_vec()[..8].try_into().unwrap(),
		))
	}

	pub fn as_bytes(&self) -> [u8; 8] {
		self.0.to_be_bytes()
	}

	pub fn to_base64(&self) -> String {
		base64::encode_config(&self.0.to_be_bytes(), base64::URL_SAFE)
	}
}

impl PartialEq<u64> for Uid {
	fn eq(&self, other: &u64) -> bool {
		&self.0 == other
	}
}

impl PartialEq<Uid> for u64 {
	fn eq(&self, other: &Uid) -> bool {
		self == &other.0
	}
}

impl FromStr for Uid {
	type Err = String;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let bytes = base64::decode_config(s, base64::URL_SAFE).map_err(|e| e.to_string())?;

		if bytes.len() != 8 {
			return Err(String::from("wrong length"));
		}

		let mut array = [0u8; 8];
		array.copy_from_slice(&bytes);

		Ok(Uid(u64::from_be_bytes(array)))
	}
}

impl Serialize for Uid {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&self.to_base64())
	}
}

impl<'de> Deserialize<'de> for Uid {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		struct Base64Visitor;

		impl<'de> Visitor<'de> for Base64Visitor {
			type Value = Uid;

			fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
				formatter.write_str("a base64-encoded u64 string")
			}

			fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
			where
				E: de::Error,
			{
				Ok(Uid::from_str(value).map_err(de::Error::custom)?)
			}
		}

		deserializer.deserialize_str(Base64Visitor)
	}
}

#[cfg(test)]
mod tests {
	use std::str::FromStr;

	use super::Uid;

	#[test]
	fn test_deserialize_from_php() {
		assert_eq!(
			6717713287347927653,
			Uid::from_str("XTocpJNLemU=").unwrap().0
		);
		assert_eq!(
			1364355021410530935,
			Uid::from_str("Eu8pqc6x9nc=").unwrap().0
		);
		assert_eq!(
			6194032148428143539,
			Uid::from_str("VfWfa-5ou7M=").unwrap().0
		);
	}

	#[test]
	fn test_empty() {
		assert_eq!(Uid::from_bytes(b""), 16406829232824261652);
	}

	#[test]
	fn test_non_zero_output_for_zeroes() {
		// any extra zero bit should lead to a diferent result
		assert_eq!(Uid::from_bytes(&[0u8]), 7940984811893783192);
		assert_eq!(Uid::from_bytes(&[0u8, 0]), 10854403881223488966);
		assert_eq!(Uid::from_bytes(&[0u8, 0, 0]), 8115065177273508417);
	}

	#[test]
	fn test_arbitrary() {
		assert_eq!(9572568648884945950, Uid::from_bytes(b"0123456789"));
	}
}
