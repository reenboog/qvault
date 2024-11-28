use base64::DecodeError;
use serde::de::Visitor;
use serde::de::{Error, Unexpected};
use serde::{Deserializer, Serializer};

// A wrapper for blob serialization as a base64 encoded string.
pub struct Base64BlobRef<'a>(&'a [u8]);
impl<'a> From<&'a [u8]> for Base64BlobRef<'a> {
	fn from(value: &'a [u8]) -> Self {
		Self(value)
	}
}

struct Base64Visitor;
struct OptionalBase64Visitor;

impl<'de> Visitor<'de> for Base64Visitor {
	type Value = Vec<u8>;

	fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(formatter, "Expected base64 encoded string")
	}

	fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
	where
		E: serde::de::Error,
	{
		let decode_result = base64::decode(s);
		match decode_result {
			Ok(value) => Ok(value),
			Err(error) => match error {
				DecodeError::InvalidByte(_, _) => Err(E::invalid_value(Unexpected::Str(s), &self)),
				DecodeError::InvalidLastSymbol(_, _) => {
					Err(E::invalid_value(Unexpected::Str(s), &self))
				}
				DecodeError::InvalidLength => Err(E::invalid_length(s.len(), &self)),
			},
		}
	}
}

impl<'de> Visitor<'de> for OptionalBase64Visitor {
	type Value = Option<Vec<u8>>;

	fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(formatter, "Expected optional base64 encoded string")
	}

	fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
	where
		D: Deserializer<'de>,
	{
		let result = deserializer.deserialize_str(Base64Visitor {});
		result.map(|value| Some(value))
	}

	fn visit_none<E>(self) -> Result<Self::Value, E>
	where
		E: Error,
	{
		Ok(None)
	}
}

impl serde::Serialize for Base64BlobRef<'_> {
	fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
		serializer.serialize_str(&base64::encode(self.0))
	}
}

pub fn serialize_vec_optional_base64<S: Serializer>(
	blob: &Option<Vec<u8>>,
	serializer: S,
) -> Result<S::Ok, S::Error> {
	match blob {
		Some(value) => serialize_vec_base64(value, serializer),
		None => Err(serde::ser::Error::custom(
			"serialize only when Option has some value",
		)),
	}
}

pub fn deserialize_vec_optional_base64<'de, D: Deserializer<'de>>(
	deserializer: D,
) -> Result<Option<Vec<u8>>, D::Error> {
	deserializer.deserialize_option(OptionalBase64Visitor {})
}

pub fn deserialize_vec_base64<'de, D: Deserializer<'de>>(
	deserializer: D,
) -> Result<Vec<u8>, D::Error> {
	deserializer.deserialize_str(Base64Visitor {})
}

pub fn serialize_vec_base64<S: Serializer>(
	blob: &Vec<u8>,
	serializer: S,
) -> Result<S::Ok, S::Error> {
	serializer.serialize_str(base64::encode(blob.as_slice()).as_str())
}

pub fn deserialize_array_base64<'de, D, const N: usize>(
	deserializer: D,
) -> Result<[u8; N], D::Error>
where
	D: Deserializer<'de>,
{
	struct Base64Visitor<const N: usize>;

	impl<'de, const N: usize> Visitor<'de> for Base64Visitor<N> {
		type Value = [u8; N];

		fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
			formatter.write_str("a valid base64 string")
		}

		fn visit_str<E>(self, v: &str) -> Result<[u8; N], E>
		where
			E: serde::de::Error,
		{
			let decoded = base64::decode(v).map_err(E::custom)?;
			let mut array = [0u8; N];

			if decoded.len() != N {
				return Err(E::custom(format!("expected a byte array of length {}", N)));
			}

			array.copy_from_slice(&decoded);

			Ok(array)
		}
	}

	deserializer.deserialize_str(Base64Visitor::<N>)
}

pub fn serialize_array_base64<S, const N: usize>(
	blob: &[u8; N],
	serializer: S,
) -> Result<S::Ok, S::Error>
where
	S: Serializer,
{
	serializer.serialize_str(&base64::encode(blob))
}

#[cfg(test)]
mod tests {
	#[test]
	fn test_deserialize_optional_base64() {
		use super::deserialize_vec_optional_base64;
		use serde::Deserialize;

		#[derive(Deserialize, Debug, PartialEq, Eq)]
		struct HelperType {
			#[serde(default, deserialize_with = "deserialize_vec_optional_base64")]
			value: Option<Vec<u8>>,
		}

		let deserialized_value: HelperType = serde_json::from_str(r#"{"value": "AQID"}"#).unwrap();
		let deserialized_null: HelperType = serde_json::from_str(r#"{"value": null}"#).unwrap();
		let deserialized_missing: HelperType = serde_json::from_str(r#"{}"#).unwrap();

		assert_eq!(
			HelperType {
				value: Some(vec![1, 2, 3]),
			},
			deserialized_value
		);
		assert_eq!(HelperType { value: None }, deserialized_null);
		assert_eq!(HelperType { value: None }, deserialized_missing);
	}

	#[test]
	fn test_serialize_optional_base64() {
		use super::serialize_vec_optional_base64;
		use serde::Serialize;

		#[derive(Serialize, Debug, PartialEq, Eq)]
		struct HelperType {
			#[serde(
				skip_serializing_if = "Option::is_none",
				serialize_with = "serialize_vec_optional_base64"
			)]
			value: Option<Vec<u8>>,
		}

		let serialized_value = serde_json::to_string(&HelperType {
			value: Some(vec![1, 2, 3]),
		})
		.unwrap();
		assert_eq!(r#"{"value":"AQID"}"#, serialized_value);

		let serialized_value = serde_json::to_string(&HelperType { value: None }).unwrap();
		assert_eq!(r#"{}"#, serialized_value);
	}
}
