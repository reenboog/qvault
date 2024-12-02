use serde::{Deserialize, Serialize};

use crate::{
	base64_blobs::{deserialize_vec_base64, serialize_vec_base64},
	salt::Salt,
};

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Encrypted {
	#[serde(
		serialize_with = "serialize_vec_base64",
		deserialize_with = "deserialize_vec_base64"
	)]
	pub ct: Vec<u8>,
	pub salt: Salt,
}
