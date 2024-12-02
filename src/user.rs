use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{
	aes_gcm,
	database::{self, SeedById},
	encrypted, hkdf,
	id::Uid,
	identity::{self, Identity},
	password_lock,
	register::LockedUser,
	salt::Salt,
	seeds::{
		self, ctx_to_sign, Bundle, Export, FinishInviteIntent, Import, Invite, InviteIntent,
		LockedShare, Seed, Sorted, ROOT_ID,
	},
	vault::{FileSystem, LockedNode},
};

#[derive(Debug, PartialEq)]
pub enum Error {
	BadJson,
	WrongPass,
	BadSalt,
	BadKey,
	CorruptData,
	NoAccess,
}

// used by admins only, so it's email-based signup
#[derive(Serialize, Deserialize)]
pub struct Signup {
	pub email: String,
	pub user: LockedUser,
}

// used by admins only, so it's email-based login
#[derive(Serialize, Deserialize)]
pub struct Login {
	pub email: String,
}

pub(crate) const GOD_ID: u64 = 0;

#[derive(PartialEq, Debug, Clone)]
pub struct User {
	pub(crate) identity: Identity,
	// things others share with me (shares); probably not requied?..
	pub(crate) imports: Vec<Import>,
	// things I share with others
	pub(crate) exports: Vec<Export>,
	pub(crate) fs: FileSystem,
	// db
}

impl User {
	pub fn is_pending_signup(&self) -> bool {
		self.imports.is_empty() && !self.is_god()
	}

	pub fn is_god(&self) -> bool {
		self.identity.id() == GOD_ID
	}

	// None means `all available`
	fn seeds_for_ids(
		&mut self,
		fs_ids: Option<&[Uid]>,
		db_ids: Option<&[database::Index]>,
	) -> Bundle {
		let mut bundle = Bundle::new();
		let identity = self.identity.private();

		if let Some(fs_ids) = fs_ids {
			// this will work for both, got and regular admins
			fs_ids.into_iter().for_each(|&id| {
				if let Ok(seed) = self.fs.share_node(id) {
					// TODO: should I throw NoAccess instead?
					bundle.set_fs(id, seed);
				}
			});
		} else {
			// if multi-space is ever considered, export imports as well
			if self.is_god() {
				bundle.set_fs(Uid::new(ROOT_ID), Self::fs_seed(identity));
			} else {
				// share all existing imports
				self.imports
					.iter()
					.flat_map(|im| &im.bundle.fs)
					.for_each(|(id, seed)| {
						bundle.set_fs(*id, seed.clone());
					});
			}
		}

		if let Some(db_ids) = db_ids {
			if self.is_god() {
				let db_seed = Self::db_seed(identity);

				db_ids.iter().for_each(|idx| {
					let id = idx.as_id();

					match idx {
						database::Index::Table { table } => {
							bundle
								.set_db(id, database::derive_table_seed_from_root(&db_seed, table));
						}
						database::Index::Column { table, column } => {
							bundle.set_db(
								id,
								database::derive_column_seed_from_root(&db_seed, table, column),
							);
						}
					}
				});
			} else {
				let imports = self
					.imports
					.iter()
					.flat_map(|im| &im.bundle.db)
					.collect::<HashMap<_, _>>();

				db_ids.iter().for_each(|idx| {
					let id = idx.as_id();

					if let Some(&seed) = imports.get(&id) {
						bundle.set_db(id, seed.clone());
					} else {
						match idx {
							database::Index::Table { table } => {
								if let Some(db_seed) = imports.get(&Uid::new(ROOT_ID)) {
									bundle.set_db(
										id,
										database::derive_table_seed_from_root(db_seed, table),
									);
								}
							}
							database::Index::Column { table, column } => {
								if let Some(table_seed) =
									imports.get(&database::id_for_table(table))
								{
									bundle.set_db(
										id,
										database::derive_column_seed_from_table(table_seed, column),
									);
								} else if let Some(db_seed) = imports.get(&Uid::new(ROOT_ID)) {
									bundle.set_db(
										id,
										database::derive_column_seed_from_root(
											db_seed, table, &column,
										),
									);
								}
							}
						}
					}
				})
			}
		} else {
			if self.is_god() {
				bundle.set_db(Uid::new(ROOT_ID), Self::db_seed(identity));
			} else {
				self.imports
					.iter()
					.flat_map(|im| &im.bundle.db)
					.for_each(|(id, seed)| {
						bundle.set_db(*id, seed.clone());
					});
			}
		}

		bundle
	}

	fn derive_seed_with_label(identity: &identity::Private, label: &[u8]) -> Seed {
		// hash identity's private keys to "root"
		let root = hkdf::Hkdf::from_ikm(
			&[
				identity.x448.as_bytes(),
				identity.ed25519.as_bytes().as_slice(),
			]
			.concat(),
		)
		.expand::<{ seeds::SEED_SIZE }>(b"root");
		// and then the resulted hash to label
		let bytes = hkdf::Hkdf::from_ikm(&root).expand::<{ seeds::SEED_SIZE }>(label);

		Seed { bytes }
	}

	pub fn db_seed(identity: &identity::Private) -> Seed {
		Self::derive_seed_with_label(identity, b"db")
	}

	pub fn fs_seed(identity: &identity::Private) -> Seed {
		Self::derive_seed_with_label(identity, b"fs")
	}

	// user_id should be known; ref_src is either activatin code or email
	pub fn start_invite_intent_with_seeds_for_ref_src(
		&self,
		ref_src: &str,
		user_id: Uid,
		fs_ids: Option<&[Uid]>,
		db_ids: Option<&[database::Index]>,
	) -> InviteIntent {
		let to_sign =
			InviteIntent::ctx_to_sign(&self.identity.id(), ref_src, &user_id, fs_ids, db_ids);
		let sig = self.identity.private().sign(&to_sign);

		// could be saved indefinitely for audit purposes
		InviteIntent {
			ref_src: ref_src.to_string(),
			sender: self.identity.public().clone(),
			sig,
			user_id,
			receiver: None,
			fs_ids: fs_ids.and_then(|ids| Some(ids.iter().cloned().collect())),
			db_ids: db_ids.and_then(|ids| Some(ids.iter().cloned().collect())),
		}
	}

	// so, an identity can be built from Mode public keys + user_id
	pub fn export_seeds_to_identity(
		&mut self,
		fs_ids: Option<&[Uid]>,
		db_ids: Option<&[database::Index]>,
		receiver: &identity::Public,
	) -> seeds::LockedShare {
		let bundle = self.seeds_for_ids(fs_ids, db_ids);
		let _pub = self.identity.public();
		let encrypted = receiver.encrypt(&bundle);
		let export = Export::from_bundle(&bundle, receiver.id());
		// sign('I share these file/db ids with this recipient')
		let sig = self.identity.private().sign(&ctx_to_sign(_pub, &export));

		seeds::LockedShare {
			sender: _pub.clone(),
			export,
			payload: encrypted,
			sig,
		}
	}

	// pin is just a password used to encrypt the seeds, if any
	// at this point, all we know is an email address and the seeds
	pub fn invite_with_seeds_for_email_and_pin(
		&mut self,
		email: &str,
		pin: &str,
		fs_ids: Option<&[Uid]>,
		db_ids: Option<&[database::Index]>,
	) -> Invite {
		let bundle = self.seeds_for_ids(fs_ids, db_ids);
		let payload = password_lock::lock(&bundle, pin).unwrap();

		let receiver_id = Uid::generate();
		let export = Export::from_bundle(&bundle, receiver_id);
		let sig = self
			.identity
			.private()
			.sign(&ctx_to_sign(self.identity.public(), &export));

		Invite {
			user_id: receiver_id,
			sender: self.identity.public().clone(),
			ref_src: email.to_string(),
			payload,
			export,
			sig,
		}
	}

	pub fn finish_invite_intents(&mut self, intents: &[InviteIntent]) -> Vec<FinishInviteIntent> {
		intents
			.iter()
			.filter_map(|int| {
				let to_sign = InviteIntent::ctx_to_sign(
					&int.sender.id(),
					&int.ref_src,
					&int.user_id,
					int.fs_ids.as_deref(),
					int.db_ids.as_deref(),
				);

				// verify these intents to make sure the backend didn't add ids, nor didn't change anything else
				if int.receiver.is_some()
					&& int.sender.id() == self.identity.id()
					&& int.sender.verify(&int.sig, &to_sign)
				{
					Some(FinishInviteIntent {
						ref_src: int.ref_src.clone(),
						share: self.export_seeds_to_identity(
							int.fs_ids.as_deref(),
							int.db_ids.as_deref(),
							int.receiver.as_ref().unwrap(),
						),
					})
				} else {
					None
				}
			})
			.collect()
	}
}

impl User {
	// may fail, if not enough acces
	fn encrypt_db_entry(&self, table: &str, pt: &[u8], column: &str) -> Result<String, Error> {
		let salt = Salt::generate();
		let aes = self.aes_for_entry_in_table(table, column, salt.clone())?;
		let ct = aes.encrypt(pt);
		let encrypted = encrypted::Encrypted { ct, salt };

		Ok(serde_json::to_string(&encrypted).unwrap())
	}

	// may fail, if not enough access
	fn decrypt_db_entry(
		&self,
		table: &str,
		encrypted: &str,
		column: &str,
	) -> Result<Vec<u8>, Error> {
		let encrypted: encrypted::Encrypted =
			serde_json::from_str(encrypted).map_err(|_| Error::BadJson)?;
		let aes = self.aes_for_entry_in_table(table, column, encrypted.salt)?;

		aes.decrypt(&encrypted.ct).map_err(|_| Error::BadKey)
	}

	// TODO: test for fine-grained access control
	fn aes_for_entry_in_table(
		&self,
		table: &str,
		column: &str,
		salt: Salt,
	) -> Result<aes_gcm::Aes, Error> {
		let bundles = self
			.imports
			.iter()
			.map(|s| s.bundle.db.clone())
			.collect::<Vec<_>>();

		let seed = if let Some(seed_from_col) =
			bundles.seed_by_id(database::id_for_column(table, column), |s| {
				// do I have a seed for this specific column?
				database::derive_entry_seed_from_column(s, &salt)
			}) {
			Ok(seed_from_col)
		} else if let Some(seed_from_table) =
			bundles.seed_by_id(database::id_for_table(table), |s| {
				// do I have a seed for this specific table?
				database::derive_entry_seed_from_table(s, column, &salt)
			}) {
			Ok(seed_from_table)
		} else if let Some(seed_from_root) = bundles.seed_by_id(Uid::new(ROOT_ID), |s| {
			// do I have a root seed?
			database::derive_entry_seed_from_root(s, table, column, &salt)
		}) {
			Ok(seed_from_root)
		} else if self.is_god() {
			// so, I'm god, hence I can derive any seed
			Ok(database::derive_entry_seed_from_root(
				&Self::db_seed(self.identity.private()),
				table,
				column,
				&salt,
			))
		} else {
			Err(Error::NoAccess)
		}?;

		let key_iv = hkdf::Hkdf::from_ikm(&seed.bytes)
			.expand_no_info::<{ aes_gcm::Key::SIZE + aes_gcm::Iv::SIZE }>();

		Ok(aes_gcm::Aes::from(&key_iv))
	}
}

impl User {
	// FIXME: sign as well
	//
	pub fn encrypt_announcement(&self, msg: &str) -> Result<String, Error> {
		self.encrypt_db_entry("messages", msg.as_bytes(), "text")
	}

	pub fn decrypt_announcement(&self, encrypted: &str) -> Result<String, Error> {
		let pt = self.decrypt_db_entry("messages", encrypted, "text")?;

		String::from_utf8(pt).map_err(|_| Error::CorruptData)
	}
}

// used by password-protected accounts only (only admins currently)
pub fn unlock_with_master_key(locked: &LockedUser, mk: &aes_gcm::Aes) -> Result<User, Error> {
	let _priv = locked.encrypted_priv.as_ref().ok_or(Error::CorruptData)?;
	let decrypted_priv =
		password_lock::unlock_with_master_key(mk, &_priv.ct).map_err(|_| Error::BadKey)?;

	let _priv: identity::Private =
		serde_json::from_slice(&decrypted_priv).map_err(|_| Error::BadJson)?;

	unlock_with_params(&_priv, &locked._pub, &locked.shares, &locked.roots)
}

pub(crate) fn unlock_with_params(
	_priv: &identity::Private,
	_pub: &identity::Public,
	shares: &[LockedShare],
	roots: &[LockedNode],
) -> Result<User, Error> {
	// for god, there should be one LockedNode (or more, if root's children) and no imports, so
	// use use.fs_seed instead for admins, there could be several LockedNodes (subroots +
	// children depending on depth) and LockedShares needed to decrypt the nodes

	// failing always, even if there's just one forged share is not an option, since it's a potential
	// ddos initiated by a compromised server basically, hence, I simply ignore any fake shares
	// TODO: alternatively, a log could be introduced to collect any forged shares for manual inspection

	// filter locked shares for export and import

	let imports = shares
		.iter()
		.filter_map(|s| {
			if s.export.receiver == _pub.id() {
				if let Ok(ref bytes) = _priv.decrypt(&s.payload) {
					if let Ok(bundle) = serde_json::from_slice::<Bundle>(bytes) {
						let to_sign = ctx_to_sign(&s.sender, &s.export);
						// make sure exports haven't been forged: verify sig + quantity
						if s.sender.verify(&s.sig, &to_sign)
							&& bundle.fs.keys().cloned().collect::<Vec<_>>().sorted()
								== s.export.fs.sorted()
							&& bundle.db.keys().cloned().collect::<Vec<_>>().sorted()
								== s.export.db.sorted()
						{
							Some(Import {
								sender: s.sender.clone(),
								bundle,
							})
						} else {
							None
						}
					} else {
						None
					}
				} else {
					None
				}
			} else {
				None
			}
		})
		.collect::<Vec<_>>();
	let exports = shares
		.iter()
		.filter_map(|s| {
			// I can't decrypt payloads here, since each is encrypted to a recipient's public key
			if s.sender.id() == _pub.id() {
				let to_sign = ctx_to_sign(&s.sender, &s.export);

				if s.sender.verify(&s.sig, &to_sign) {
					Some(s.export.clone())
				} else {
					None
				}
			} else {
				None
			}
		})
		.collect();

	let bundles = if _pub.is_god() {
		[(Uid::new(ROOT_ID), User::fs_seed(&_priv))]
			.into_iter()
			.collect()
	} else {
		imports.iter().flat_map(|im| im.bundle.fs.clone()).collect()
	};

	// this is what is required for a Mode user to rebuild
	let fs = FileSystem::from_locked_nodes(&roots, &bundles);

	Ok(User {
		identity: Identity {
			_priv: _priv.clone(),
			_pub: _pub.clone(),
		},
		imports,
		exports,
		fs,
	})
}

pub fn unlock_with_pass(pass: &str, locked: &LockedUser) -> Result<User, Error> {
	let _priv = locked.encrypted_priv.as_ref().ok_or(Error::CorruptData)?;
	let mk =
		password_lock::decrypt_master_key(&_priv.master_key, pass).map_err(|_| Error::WrongPass)?;

	unlock_with_master_key(locked, &mk)
}

#[cfg(test)]
mod tests {
	use std::collections::HashMap;

	use crate::{
		database,
		id::Uid,
		register::{signup_as_admin_with_pin, signup_as_god, NewUser},
		seeds::{Welcome, ROOT_ID},
		user::{unlock_with_pass, User},
	};

	#[test]
	fn test_encrypt_announcement() {
		let god_pass = "god_pass";
		let NewUser {
			locked: locked_user,
			user: mut god,
		} = signup_as_god(&god_pass).unwrap();

		let pin = "1234567890";
		let invite = god.invite_with_seeds_for_email_and_pin("alice.mail.com", pin, None, None);
		let welcome = Welcome {
			user_id: invite.user_id,
			sender: invite.sender,
			imports: invite.payload,
			nodes: locked_user.roots.clone(),
			sig: invite.sig,
		};
		let admin_pass = "admin_pass";
		let NewUser {
			locked: mut locked_admin,
			user: admin,
		} = signup_as_admin_with_pin(admin_pass, &welcome, pin).unwrap();

		locked_admin.roots = locked_user.roots;

		let unlocked_admin = unlock_with_pass(admin_pass, &locked_admin).unwrap();

		assert_eq!(admin, unlocked_admin);

		for i in 0..10 {
			let msg = format!("hi there {}", i);
			let ct = god.encrypt_announcement(&msg).unwrap();
			let pt = god.decrypt_announcement(&ct).unwrap();

			assert_eq!(msg, pt);

			let pt = unlocked_admin.decrypt_announcement(&ct).unwrap();

			assert_eq!(msg, pt);
		}
	}

	#[test]
	fn test_export_db_seeds() {
		let god_pass = "god_pass";
		let NewUser {
			locked: locked_user,
			user: mut god,
		} = signup_as_god(&god_pass).unwrap();

		let pin = "1234567890";
		// share all root seeds
		let invite = god.invite_with_seeds_for_email_and_pin("adaml@mail.com", pin, None, None);
		let roots = locked_user.roots;
		let welcome = Welcome {
			user_id: invite.user_id,
			sender: invite.sender,
			imports: invite.payload,
			nodes: roots.clone(),
			sig: invite.sig,
		};
		let adam_pass = "adam_pass";
		let NewUser {
			locked: _,
			user: mut adam,
		} = signup_as_admin_with_pin(adam_pass, &welcome, pin).unwrap();

		// all this user has for db is the root seed of the god
		let db_seeds = adam
			.imports
			.iter()
			.flat_map(|im| im.bundle.db.clone())
			.collect::<HashMap<_, _>>();
		assert_eq!(db_seeds.len(), 1);
		assert_eq!(
			db_seeds.get(&Uid::new(ROOT_ID)),
			Some(&User::db_seed(god.identity.private()))
		);

		// now adam selectively shares some seeds with eve
		let eve_pin = "666";
		let eve_pass = "eve_pass";
		let idx_users = database::Index::Table {
			table: "users".to_string(),
		};
		let idx_companies = database::Index::Table {
			table: "companies".to_string(),
		};
		let idx_sales_id = database::Index::Column {
			table: "sales".to_string(),
			column: "id".to_string(),
		};
		let idx_requests_content = database::Index::Column {
			table: "requests".to_string(),
			column: "content".to_string(),
		};
		let eve_invite = adam.invite_with_seeds_for_email_and_pin(
			"eve@mail.com",
			eve_pin,
			None,
			Some(&[
				idx_users.clone(),
				idx_companies.clone(),
				idx_sales_id.clone(),
				idx_requests_content.clone(),
			]),
		);
		let welcome = Welcome {
			user_id: eve_invite.user_id,
			sender: eve_invite.sender,
			imports: eve_invite.payload,
			nodes: roots.clone(),
			sig: eve_invite.sig,
		};
		let NewUser {
			locked: _,
			user: mut eve,
		} = signup_as_admin_with_pin(eve_pass, &welcome, eve_pin).unwrap();

		// eve should have 4 shares
		let db_seeds = eve
			.imports
			.iter()
			.flat_map(|im| im.bundle.db.clone())
			.collect::<HashMap<_, _>>();
		assert_eq!(db_seeds.len(), 4);
		assert_eq!(db_seeds.get(&Uid::new(ROOT_ID)), None,);
		vec![
			idx_users,
			idx_companies.clone(),
			idx_sales_id,
			idx_requests_content,
		]
		.into_iter()
		.for_each(|idx| {
			assert!(db_seeds.contains_key(&idx.as_id()));
		});

		// now eve share all her shares with abel
		let abel_pin = "777";
		let abel_pass = "abel_pass";
		let abel_invite =
			eve.invite_with_seeds_for_email_and_pin("abel@mail.com", abel_pin, None, None);
		let welcome = Welcome {
			user_id: abel_invite.user_id,
			sender: abel_invite.sender,
			imports: abel_invite.payload,
			nodes: roots.clone(),
			sig: abel_invite.sig,
		};
		let NewUser {
			locked: _,
			user: mut eve,
		} = signup_as_admin_with_pin(abel_pass, &welcome, abel_pin).unwrap();
		let db_seeds = eve
			.imports
			.iter()
			.flat_map(|im| im.bundle.db.clone())
			.collect::<HashMap<_, _>>();
		assert_eq!(db_seeds.len(), 4);

		// now eve shares some of her shares with cain
		let cain_pin = "000";
		let cain_pass = "cain_pass";
		// try giving less than available (ok)
		let idx_users_names = database::Index::Column {
			table: "users".to_string(),
			column: "name".to_string(),
		};
		let idx_users_age = database::Index::Column {
			table: "users".to_string(),
			column: "age".to_string(),
		};
		// try giving more than available (not ok)
		let idx_sales = database::Index::Table {
			table: "sales".to_string(),
		};
		let cain_invite = eve.invite_with_seeds_for_email_and_pin(
			"eve@mail.com",
			cain_pin,
			None,
			Some(&[
				idx_users_names.clone(),
				idx_users_age.clone(),
				// just share an available index
				idx_companies.clone(),
				// should not be shared, since it's more than eve has
				idx_sales,
				// a few random indices
				database::Index::Table {
					table: "123".to_string(),
				},
				database::Index::Column {
					table: "abc".to_ascii_lowercase(),
					column: "def".to_string(),
				},
			]),
		);
		let welcome = Welcome {
			user_id: cain_invite.user_id,
			sender: cain_invite.sender,
			imports: cain_invite.payload,
			nodes: roots,
			sig: cain_invite.sig,
		};
		let NewUser {
			locked: _,
			user: cain,
		} = signup_as_admin_with_pin(cain_pass, &welcome, cain_pin).unwrap();

		// eve should have 4 shares
		let db_seeds = cain
			.imports
			.iter()
			.flat_map(|im| im.bundle.db.clone())
			.collect::<HashMap<_, _>>();
		assert_eq!(db_seeds.len(), 3);
		// cain should only have what was allowed for eve to share, not what she intended to share
		vec![idx_users_names, idx_users_age, idx_companies]
			.into_iter()
			.for_each(|idx| {
				assert!(db_seeds.contains_key(&idx.as_id()));
			});
	}
}
