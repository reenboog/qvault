use serde::{Deserialize, Serialize};

use crate::{
	ed25519,
	id::Uid,
	identity::{self},
	password_lock,
	seeds::{self, Bundle, Export, Import, InviteIntent, LockedShare, Welcome},
	user::{self, User},
	vault::{FileSystem, LockedNode},
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
	pub(crate) encrypted_priv: Option<password_lock::Lock>,
	#[serde(rename = "pub")]
	pub(crate) _pub: identity::Public,
	// exports & imports will be decoded from this; god has empty imports, always
	// sent, ackend and encrypted shared
	pub(crate) shares: Vec<LockedShare>,
	// sent and optionally acked shares (could be useful to cancel, if not yet accepted)
	pub(crate) pending_invite_intents: Vec<InviteIntent>,
	// get_nodes(locked_shares(user_id == share.receiver | user_id == 0 then node_id_root).export.fs.ids + children)
	// TODO: include a hash of the hierarchy for later checks
	pub(crate) roots: Vec<LockedNode>,
}

#[derive(PartialEq, Debug)]
pub struct NewUser {
	// to be sent to the backend
	pub(crate) locked: LockedUser,
	// to be used internally
	pub(crate) user: User,
}

// registration to upload (encrypted & encoded)
pub(crate) fn signup_as_god(pass: &str) -> Result<NewUser, Error> {
	let identity = identity::Identity::generate(Uid::new(user::GOD_ID));
	let (fs, root) = FileSystem::new(&User::fs_seed(identity.private()), &identity);

	signup_with_params(pass, identity, None, fs, vec![root])
}

pub(crate) fn signup_as_admin_with_pin(
	pass: &str,
	welcome: &Welcome,
	pin: &str,
) -> Result<NewUser, Error> {
	let bundle = password_lock::unlock(&welcome.imports, pin).map_err(|_| Error::WrongPass)?;
	let bundle: Bundle = serde_json::from_slice(&bundle).map_err(|_| Error::BadJson)?;
	let import = Import {
		sender: welcome.sender.clone(),
		bundle: bundle.clone(),
	};

	let fs = FileSystem::from_locked_nodes(&welcome.nodes, &bundle.fs);

	signup_with_params(
		pass,
		identity::Identity::generate(welcome.user_id),
		Some((import, welcome.sig.clone())),
		fs,
		vec![],
	)
}

pub(crate) fn signup_as_admin_no_pin(
	email: &str,
	pass: &str,
	intent: InviteIntent,
) -> Result<LockedUser, Error> {
	let to_sign = InviteIntent::ctx_to_sign(
		&intent.sender.id(),
		&email,
		&intent.user_id,
		intent.fs_ids.as_deref(),
		intent.db_ids.as_deref(),
	);

	if intent.sender.verify(&intent.sig, &to_sign) && email == intent.ref_src {
		let identity = identity::Identity::generate(intent.user_id);
		let locked_priv = password_lock::lock(identity.private(), pass).unwrap();

		Ok(LockedUser {
			encrypted_priv: Some(locked_priv),
			_pub: identity.public().clone(),
			shares: Vec::new(),
			roots: Vec::new(),
			pending_invite_intents: Vec::new(),
		})
	} else {
		Err(Error::ForgedSig)
	}
}

fn signup_with_params(
	pass: &str,
	identity: identity::Identity,
	import: Option<(Import, ed25519::Signature)>,
	fs: FileSystem,
	nodes_to_upload: Vec<LockedNode>,
) -> Result<NewUser, Error> {
	let locked_priv = password_lock::lock(identity.private(), pass).unwrap();
	let _pub = identity.public();
	let id = identity.id();
	let imports = import.map_or(Vec::new(), |s| vec![s]);
	let shares = imports
		.iter()
		.map(|im| {
			let sender = im.0.sender.clone();
			let bundle = im.0.bundle.clone();
			let export = Export::from_bundle(&bundle, id);
			let to_sign = seeds::ctx_to_sign(&sender, &export);
			let sig = im.1.clone();

			if sender.verify(&sig, &to_sign) {
				Ok(LockedShare {
					sender,
					export,
					payload: _pub.encrypt(bundle),
					sig,
				})
			} else {
				Err(Error::ForgedSig)
			}
		})
		.collect::<Result<_, _>>()?;

	let locked_user = LockedUser {
		encrypted_priv: Some(locked_priv),
		_pub: _pub.clone(),
		shares,
		roots: nodes_to_upload,
		pending_invite_intents: Vec::new(),
	};

	Ok(NewUser {
		locked: locked_user,
		user: User {
			identity,
			imports: imports.into_iter().map(|im| im.0).collect(),
			// the inviting party will have this updated after the first login following the recipient's registration
			exports: Vec::new(),
			fs,
		},
	})
}

/*

	can A override seeds shared by B for C? - no, since they are shared individually

	- god sees and knows everything, hence no need to share anything with him
	- admins can share pieces of their wisdom with other admins
	- for now, god will be sharing only his root seeds (whole fs and db)
	- admins should be able to re-share root seeds as well

	admins
	id		pub_identity		priv_identity		shares (list of ids)
	god		xgod, edgod			xgod, edgod			_
	mngr	xmngr, edmngr		xmngr, edmngr		docs, hr; users, msgs
	dev		xdev, eddev			xdev, eddev			docs, repo, ci; msgs

	user.share(seeds, public_key) -> share { owner, target, seeds }

	pending_invites
	id			seeds
	qa			reports; _
	audit 	blog, repo; msgs

	invite
	id		owner		target_email		encrypted_seeds		sig
	1			god			alice@mail			Lock { ... }			0xaf12f
	2			god			bob@mail				Lock { ... }			0xffbed
	3			alice		eve@mail				Lock { ... }			0xaeae1

	share
	id		sender	receiver	encrypted_seeds				sig				epoxrt (ids)
	1			god			alice			Encrypted { ... }			0xaf12f		[1, 2, 3]
	2			god			bob				Encrypted { ... }			0xffbed		[4, 5]
	3			alice		eve				Encrypted { ... }			0xaeae1		[6]

*/

#[cfg(test)]
mod tests {
	use crate::{
		id::Uid,
		seeds::{Invite, Welcome, ROOT_ID},
		user::{self},
		vault::NewNodeReq,
	};

	use super::{signup_as_admin_no_pin, signup_as_admin_with_pin, signup_as_god, NewUser};

	#[test]
	fn test_unlock() {
		let pass = "simple_pass";
		let NewUser {
			locked: locked_user,
			user,
		} = signup_as_god(&pass).unwrap();
		let unlock = user::unlock_with_pass(pass, &locked_user);

		assert_eq!(Ok(user), unlock);
	}

	#[test]
	fn test_register_admin_and_unlock() {
		let god_pass = "god_pass";
		let NewUser {
			locked: locked_god,
			user: mut god,
		} = signup_as_god(&god_pass).unwrap();

		let pin = "1234567890";
		let invite = god.invite_with_seeds_for_email_and_pin("alice.mail.com", pin, None, None);
		let welcome = Welcome {
			user_id: invite.user_id,
			sender: invite.sender,
			imports: invite.payload,
			// pretend these nodes are coming from the backend
			nodes: locked_god.roots.clone(),
			sig: invite.sig,
		};
		let admin_pass = "admin_pass";
		let NewUser {
			locked: mut locked_admin,
			user: admin,
		} = signup_as_admin_with_pin(admin_pass, &welcome, pin).unwrap();

		// pretend the backend returns all locked nodes for this user
		locked_admin.roots = locked_god.roots;

		let unlocked_admin = user::unlock_with_pass(admin_pass, &locked_admin).unwrap();

		assert_eq!(admin, unlocked_admin);
	}

	#[test]
	fn test_register_no_pin() {
		let god_pass = "god_pass";
		let NewUser {
			locked: locked_god,
			user: mut god,
		} = signup_as_god(&god_pass).unwrap();
		let root_id = Uid::new(ROOT_ID);
		let NewNodeReq { node, locked_node } =
			god.fs.mkdir(root_id, "test", &god.identity).unwrap();
		_ = god.fs.insert_node(node.clone());
		let admin_email = "admin@mail.com";
		// 1 create an intent
		let intent = god.start_invite_intent_with_seeds_for_ref_src(
			admin_email,
			Uid::generate(),
			None,
			None,
		);
		let admin_pass = "123";
		// 2 prentend to have fetch the intent & signup
		let mut locked_admin =
			signup_as_admin_no_pin(&admin_email, &admin_pass, intent.clone()).unwrap();
		// 3 pretend to have finished the intent by sharing the seeds
		let export = god.export_seeds_to_identity(
			intent.fs_ids.as_deref(),
			intent.db_ids.as_deref(),
			&locked_admin._pub,
		);

		locked_admin.shares = vec![export];
		locked_admin.roots = vec![locked_god.roots[0].clone(), locked_node];

		// 4 now, when unlocking it's just regular shares
		let unlocked_admin = user::unlock_with_pass(&admin_pass, &locked_admin).unwrap();

		assert!(unlocked_admin.fs.ls_dir(node.id).is_ok());
		assert_eq!(unlocked_admin.fs.ls_dir(node.id), god.fs.ls_dir(node.id));
		assert!(unlocked_admin.fs.ls_dir(root_id).is_ok());
		assert_eq!(unlocked_admin.fs.ls_dir(root_id), god.fs.ls_dir(root_id));

		// 5 make sure db access is ok as well
		assert!(unlocked_admin
			.decrypt_announcement(&god.encrypt_announcement("hey there").unwrap())
			.is_ok())
	}

	#[test]
	fn test_register_admin_by_admin() {
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
			nodes: locked_user.roots,
			sig: invite.sig,
		};
		let admin_pass = "admin_pass";
		let NewUser {
			locked: locked_user,
			user: mut admin,
		} = signup_as_admin_with_pin(admin_pass, &welcome, pin).unwrap();

		let new_pin = "555";
		let new_pass = "new_admin_pass";
		let new_invite =
			admin.invite_with_seeds_for_email_and_pin("bob.mail.com", &new_pin, None, None);
		let welcome = Welcome {
			user_id: new_invite.user_id,
			sender: new_invite.sender,
			imports: new_invite.payload,
			nodes: locked_user.roots,
			sig: new_invite.sig,
		};
		let NewUser {
			locked: new_admin_locked,
			user: new_admin,
		} = signup_as_admin_with_pin(new_pass, &welcome, new_pin).unwrap();
		let new_unlocked_admin = user::unlock_with_pass(new_pass, &new_admin_locked).unwrap();

		assert_eq!(new_admin, new_unlocked_admin);
	}
}
