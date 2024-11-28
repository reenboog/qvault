// Accepts a type name, outputs a generic key type, eg PrivateKey<T, SIZE>, PublicKey<T, SIZE>, etc
macro_rules! key {
	($type: ident) => {
		#[derive(Debug, PartialEq)]
		pub struct $type<T, const SIZE: usize> {
			bytes: [u8; SIZE],
			_marker: std::marker::PhantomData<T>,
		}

		impl<T, const SIZE: usize> $type<T, SIZE> {
			// TODO: rename to `from_bytes`?
			pub fn new(bytes: [u8; SIZE]) -> Self {
				Self {
					bytes,
					_marker: std::marker::PhantomData,
				}
			}

			pub fn as_bytes(&self) -> &[u8; SIZE] {
				&self.bytes
			}
		}

		impl<T, const SIZE: usize> From<&[u8; SIZE]> for $type<T, SIZE> {
			fn from(bytes: &[u8; SIZE]) -> Self {
				Self::new(bytes.clone())
			}
		}

		impl<T, const SIZE: usize> TryFrom<Vec<u8>> for $type<T, SIZE> {
			type Error = std::array::TryFromSliceError;

			fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
				let slice: [u8; SIZE] = value.as_slice().try_into()?;

				Ok(Self::new(slice))
			}
		}

		impl<T, const SIZE: usize> Clone for $type<T, SIZE> {
			fn clone(&self) -> Self {
				Self::new(self.bytes.clone())
			}
		}

		impl<T, const SIZE: usize> serde::Serialize for $type<T, SIZE> {
			fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
				serializer.serialize_str(&base64::encode(self.bytes))
			}
		}

		impl<'de, T, const SIZE: usize> serde::Deserialize<'de> for $type<T, SIZE> {
			fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
			where
				D: serde::Deserializer<'de>,
			{
				struct Visitor<T, const SIZE: usize>(std::marker::PhantomData<T>);

				impl<'de, T, const SIZE: usize> serde::de::Visitor<'de> for Visitor<T, SIZE> {
					type Value = $type<T, SIZE>;

					fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
						formatter.write_str("a base64 encoded string")
					}

					fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
					where
						E: serde::de::Error,
					{
						let bytes = base64::decode(v).map_err(E::custom)?;
						let bytes: [u8; SIZE] = bytes.as_slice().try_into().map_err(E::custom)?;

						Ok($type::new(bytes))
					}
				}

				deserializer.deserialize_str(Visitor(std::marker::PhantomData))
			}
		}
	};
}

pub(crate) use key;

#[cfg(test)]
mod tests {
	use super::key;

	key!(Key);
	#[derive(Debug, PartialEq)]
	struct KeyType;
	type TestKey = Key<KeyType, 10>;

	#[test]
	fn test_as_bytes() {
		let key = TestKey::new(b"0123456789".to_owned());

		assert_eq!(key.as_bytes(), b"0123456789");
	}

	#[test]
	fn test_from_bytes() {
		let key: TestKey = b"0123456789".into();

		assert_eq!(key.as_bytes(), b"0123456789");
	}

	#[test]
	fn test_try_from_vec() {
		let k0 = TestKey::try_from(b"0123456789".to_vec());

		assert!(k0.is_ok());

		let k1 = TestKey::try_from(b"0123".to_vec());

		assert!(k1.is_err());
	}

	#[test]
	fn test_partial_eq() {
		let k0 = TestKey::try_from(b"0123456789".to_vec()).unwrap();
		let k1 = TestKey::try_from(b"0123456789".to_vec()).unwrap();

		assert_eq!(k0, k1);

		#[derive(Debug, PartialEq)]
		struct KeyType2;

		let _k2 = Key::<KeyType2, 10>::try_from(b"0123456789".to_vec()).unwrap();

		// this won't compile, since the keys have different types
		// assert_eq!(k1, k2);
	}

	#[test]
	fn test_serialize_deserialize() {
		let key = TestKey::try_from(b"0123456789".to_vec()).unwrap();
		let serialized = serde_json::to_string(&key).unwrap();
		let deserialized = serde_json::from_str(&serialized).unwrap();

		assert_eq!(key, deserialized);
	}
}
