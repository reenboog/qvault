use serde::{Deserialize, Serialize};

use crate::{
	identity::{self},
	password_lock,
	seeds::{InviteIntent, LockedShare},
	vault::LockedNode,
};

#[derive(PartialEq, Debug)]
pub enum Error {
	WrongPass,
	// FIXME: include json string
	BadJson,
	ForgedSig,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct LockedUser {
	// password-encrypted identity::Private; used by admins only
	pub encrypted_priv: Option<password_lock::Lock>,
	#[serde(rename = "pub")]
	pub _pub: identity::Public,
	// exports & imports will be decoded from this; god has empty imports, always
	// sent, ackend and encrypted shared
	pub shares: Vec<LockedShare>,
	// sent and optionally acked shares (could be useful to cancel, if not yet accepted)
	pub pending_invite_intents: Vec<InviteIntent>,
	// get_nodes(locked_shares(user_id == share.receiver | user_id == 0 then node_id_root).export.fs.ids + children)
	// TODO: include a hash of the hierarchy for later checks
	pub roots: Vec<LockedNode>,
}
