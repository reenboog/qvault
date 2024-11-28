use crate::{id::Uid, key::key};

key!(PublicKey);

impl<T, const SIZE: usize> PublicKey<T, SIZE> {
	pub fn id(&self) -> Uid {
		Uid::from_bytes(&self.bytes)
	}
}

#[cfg(test)]
mod tests {
	use super::PublicKey;

	struct TestKeyType;
	type TestPublicKey = PublicKey<TestKeyType, 10>;

	#[test]
	fn test_id() {
		let key = TestPublicKey::new(b"0123456789".to_owned());
		let id = key.id();

		assert_eq!(9572568648884945950, id);
	}
}
