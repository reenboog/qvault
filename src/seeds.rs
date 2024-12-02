use std::collections::HashMap;

use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
	base64_blobs::{deserialize_array_base64, serialize_array_base64},
	database, ed25519, hmac,
	id::Uid,
	identity, password_lock,
	vault::LockedNode,
};

pub(crate) const SEED_SIZE: usize = 32;
pub(crate) const ROOT_ID: u64 = 0;

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Hash)]
pub struct Seed {
	#[serde(
		serialize_with = "serialize_array_base64::<_, SEED_SIZE>",
		deserialize_with = "deserialize_array_base64::<_, SEED_SIZE>"
	)]
	pub(crate) bytes: [u8; SEED_SIZE],
}

impl Seed {
	pub fn generate() -> Self {
		let mut bytes = [0u8; SEED_SIZE];
		OsRng.fill_bytes(&mut bytes);

		Self { bytes }
	}
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
// sender can share as many bundles as he wants
pub struct Import {
	// no sig is required here; validate LockedShare instead
	pub(crate) sender: identity::Public,
	pub(crate) bundle: Bundle,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Export {
	// no sig is required here; validate LockedShare instead
	pub(crate) receiver: Uid,
	// these are ids of the exported seeds
	pub(crate) fs: Vec<Uid>,
	pub(crate) db: Vec<Uid>,
}

pub trait Sorted {
	type Item;
	fn sorted(&self) -> Vec<Self::Item>;
}

impl<T: Ord + Clone> Sorted for Vec<T> {
	type Item = T;

	fn sorted(&self) -> Vec<Self::Item> {
		let mut refs: Vec<T> = self.clone();
		refs.sort();

		refs
	}
}

impl Export {
	pub fn from_bundle(bundle: &Bundle, receiver_id: Uid) -> Self {
		Self {
			receiver: receiver_id,
			fs: bundle.fs.keys().cloned().collect(),
			db: bundle.db.keys().cloned().collect(),
		}
	}

	pub fn hash(&self) -> hmac::Digest {
		// sort first
		let bytes = self
			.fs
			.sorted()
			.iter()
			.chain(self.db.sorted().iter())
			.flat_map(|k| [k.as_bytes()].concat())
			.collect::<Vec<_>>();
		let sha = Sha256::digest([&bytes, self.receiver.as_bytes().as_slice()].concat());

		hmac::Digest(sha.into())
	}
}
pub(crate) fn ctx_to_sign(sender: &identity::Public, export: &Export) -> Vec<u8> {
	[sender.id().as_bytes().as_slice(), export.hash().as_bytes()].concat()
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
// when unlocking, the backend is to return all LockedShare where id == sender.id() || export.receiver
pub struct LockedShare {
	pub(crate) sender: identity::Public,
	// ids of the share (convenient to return roots to unlock)
	pub(crate) export: Export,
	// encrypted content of the share
	pub(crate) payload: identity::Encrypted,
	// sign({ sender, exports })
	pub(crate) sig: ed25519::Signature,
}

// used by pin-based invites only
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Invite {
	pub(crate) user_id: Uid,
	// pin needs to be shared through a trusted channel, so no need to sign
	pub(crate) sender: identity::Public,
	pub(crate) ref_src: String,
	// encrypted Bundle
	pub(crate) payload: password_lock::Lock,
	pub(crate) export: Export,
	// sign({ sender, exports })
	pub(crate) sig: ed25519::Signature,
}

// a pin-less invite intent that should be later acknowledged
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct InviteIntent {
	// email or activation code – anything used to sign up
	pub(crate) ref_src: String,
	pub(crate) sender: identity::Public,
	// sign(sender + ref_src + user_id)
	pub(crate) sig: ed25519::Signature,
	pub(crate) user_id: Uid,
	// receiver's pk which the sender is to use to finally encrypt the previously selected seeds
	pub(crate) receiver: Option<identity::Public>,
	// None means `root`
	pub(crate) fs_ids: Option<Vec<Uid>>,
	pub(crate) db_ids: Option<Vec<database::Index>>,
}

impl InviteIntent {
	pub(crate) fn ctx_to_sign(
		sender: &Uid,
		ref_src: &str,
		receiver: &Uid,
		fs_ids: Option<&[Uid]>,
		db_ids: Option<&[database::Index]>,
	) -> Vec<u8> {
		[
			&sender.as_bytes(),
			ref_src.as_bytes(),
			&receiver.as_bytes(),
			&fs_ids
				.map_or(vec![], |fs_id| {
					fs_id.iter().map(|uid| uid.as_bytes()).collect()
				})
				.concat(),
			&db_ids
				.map_or(vec![], |db_id| {
					db_id.iter().map(|idx| idx.as_id().as_bytes()).collect()
				})
				.concat(),
		]
		.concat()
	}
}

#[derive(Serialize, Deserialize)]
pub struct FinishInviteIntent {
	// email or activation code
	pub(crate) ref_src: String,
	pub(crate) share: LockedShare,
}

// used by pin-based invites only
#[derive(Serialize, Deserialize)]
pub struct Welcome {
	pub(crate) user_id: Uid,
	pub(crate) sender: identity::Public,
	pub(crate) imports: password_lock::Lock,
	// = Invite::sig
	pub(crate) sig: ed25519::Signature,
	// TODO: get_nodes(invite.export.fs.ids)
	pub(crate) nodes: Vec<LockedNode>,
}

pub type Seeds = HashMap<Uid, Seed>;

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Bundle {
	// seeds for the filesystem; a key equals to all zeroes is a root key
	// can be root
	// dir
	// file
	pub fs: Seeds,
	// seeds for the database; a key equals to all zeroes is a root key

	// can be root
	// table
	// column
	// or entry? -rather no
	pub db: Seeds,
}

impl Bundle {
	pub(crate) fn new() -> Self {
		Self {
			fs: Seeds::new(),
			db: Seeds::new(),
		}
	}

	pub fn set_fs(&mut self, id: Uid, seed: Seed) {
		self.fs.insert(id, seed);
	}

	pub fn set_db(&mut self, id: Uid, seed: Seed) {
		self.db.insert(id, seed);
	}
}
