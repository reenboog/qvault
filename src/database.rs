use serde::{Deserialize, Serialize};

use crate::{
	hkdf,
	id::Uid,
	salt::Salt,
	seeds::{self, Seed, Seeds},
};

// id	name	*email					age	*salary	position	*address	salt/iv (32 btes)
// 1	 	alice	alice@mode.io		24	10			account		usa				0xdf2d
// 2	 	bob		bob@mode.io			30	16			software	china			0xde5d
// 3	 	eve		eve@mode.io			30	12			software	russia		0xae2f
// 4	 	dave	dave@mode.io		20	22			cto				canada		0xffff

// db_root = gen()
// h_table = h(db_root + table_users)
// h_column = h(h_table + column_name)
// h_item = h(h_column + item_salt)

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub enum Index {
	Table { table: String },
	Column { table: String, column: String },
}

impl Index {
	pub fn as_id(&self) -> Uid {
		match self {
			Index::Table { table } => id_for_table(table),
			Index::Column { table, column } => id_for_column(table, column),
		}
	}
}

pub trait SeedById {
	fn seed_by_id<F>(&self, id: Uid, derive_fn: F) -> Option<Seed>
	where
		F: Fn(&Seed) -> Seed;
}

impl SeedById for Vec<Seeds> {
	fn seed_by_id<F>(&self, id: Uid, derive: F) -> Option<Seed>
	where
		F: Fn(&Seed) -> Seed,
	{
		self.iter().find_map(|b| b.get(&id).map(&derive))
	}
}

pub fn derive_table_seed_from_root(root: &Seed, table_name: &str) -> Seed {
	Seed {
		bytes: hkdf::Hkdf::from_ikm(&[root.bytes.as_slice(), table_name.as_bytes()].concat())
			.expand_no_info::<{ seeds::SEED_SIZE }>(),
	}
}

pub fn derive_column_seed_from_table(table: &Seed, column_name: &str) -> Seed {
	Seed {
		bytes: hkdf::Hkdf::from_ikm(&[table.bytes.as_slice(), column_name.as_bytes()].concat())
			.expand_no_info::<{ seeds::SEED_SIZE }>(),
	}
}

pub fn derive_entry_seed_from_column(col: &Seed, salt: &Salt) -> Seed {
	Seed {
		bytes: hkdf::Hkdf::from_ikm(&[col.bytes, salt.bytes].concat())
			.expand_no_info::<{ seeds::SEED_SIZE }>(),
	}
}

pub fn derive_entry_seed_from_table(table: &Seed, column_name: &str, salt: &Salt) -> Seed {
	let column = derive_column_seed_from_table(table, column_name);

	derive_entry_seed_from_column(&column, salt)
}

pub fn derive_entry_seed_from_root(
	root: &Seed,
	table_name: &str,
	column_name: &str,
	salt: &Salt,
) -> Seed {
	let table = derive_table_seed_from_root(root, table_name);

	derive_entry_seed_from_table(&table, column_name, salt)
}

pub fn derive_column_seed_from_root(root: &Seed, table_name: &str, column_name: &str) -> Seed {
	let table = derive_table_seed_from_root(root, table_name);

	derive_column_seed_from_table(&table, column_name)
}

pub fn id_for_column(table: &str, column: &str) -> Uid {
	Uid::from_bytes(&[table.as_bytes(), b"-", column.as_bytes()].concat())
}

pub fn id_for_table(table: &str) -> Uid {
	Uid::from_bytes(table.as_bytes())
}

#[cfg(test)]
mod tests {
	use crate::{
		database::{
			derive_column_seed_from_root, derive_column_seed_from_table,
			derive_entry_seed_from_column, derive_entry_seed_from_root,
			derive_entry_seed_from_table, derive_table_seed_from_root,
		},
		salt::Salt,
		seeds::Seed,
	};

	use super::{id_for_column, id_for_table};

	#[test]
	fn test_id_for_table() {
		let users = id_for_table("users");
		let messages = id_for_table("messages");

		assert_ne!(users, 0);
		assert_ne!(messages, 0);
		assert_ne!(users, messages);
	}

	#[test]
	fn test_id_for_column() {
		let users_id = id_for_column("users", "id");
		let users_mail = id_for_column("users", "mail");
		let messages_id = id_for_column("messages", "id");
		let mail_users = id_for_column("mail", "users");

		assert_ne!(users_id, 0);
		assert_ne!(users_mail, 0);
		assert_ne!(messages_id, 0);
		assert_ne!(mail_users, 0);
		assert_ne!(mail_users, users_mail);
		assert_ne!(messages_id, users_id);
	}

	#[test]
	fn test_seed_from_parents() {
		let root = Seed {
			bytes: b"12345678909876543211234567890981".to_owned(),
		};
		let table_name = "table";
		let column_name = "column";
		let salt = Salt::generate();
		let table = derive_table_seed_from_root(&root, table_name);
		let column = derive_column_seed_from_root(&root, table_name, column_name);

		assert_eq!(column, derive_column_seed_from_table(&table, column_name));
		assert_eq!(
			derive_entry_seed_from_column(&column, &salt),
			derive_entry_seed_from_table(&table, column_name, &salt)
		);
		assert_eq!(
			derive_entry_seed_from_table(&table, column_name, &salt),
			derive_entry_seed_from_root(&root, table_name, column_name, &salt)
		);
	}
}
