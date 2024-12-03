use std::collections::HashMap;

use crate::{
	database::{self},
	hkdf,
	id::Uid,
	identity::{self, Identity},
	seeds::{self, ctx_to_sign, Bundle, Export, Import, LockedShare, Seed, Sorted, ROOT_ID},
	vault::{FileSystem, LockedNode},
};

#[derive(Debug, PartialEq)]
pub enum Error {
	BadJson,
	NoAccess,
}

pub const GOD_ID: u64 = 0;

#[derive(PartialEq, Debug, Clone)]
pub struct User {
	pub identity: Identity,
	// things others share with me (shares); probably not requied?..
	pub imports: Vec<Import>,
	// things I share with others
	pub exports: Vec<Export>,
	pub fs: FileSystem,
}

impl User {
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
}

pub fn unlock_with_params(
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
