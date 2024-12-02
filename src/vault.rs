use std::collections::HashMap;

use crate::{
	aes_gcm::{self, Aes},
	ed25519,
	encrypted::Encrypted,
	hkdf::Hkdf,
	hmac,
	id::Uid,
	identity,
	salt::Salt,
	seeds::{self, Seed, Seeds, ROOT_ID},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(PartialEq, Debug)]
pub enum Error {
	NotFound,
	// TODO: add a description
	BadOperation,
	// TODO: add id
	NoAccess,
	ForgedSig,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct FileInfo {
	pub(crate) size: u32,
	pub(crate) key_iv: Aes,
	pub(crate) ext: String,
}

#[derive(Serialize, Deserialize)]
pub enum LockedEntry {
	File { info: FileInfo },
	// seed does not improve encryption strength directly, but
	// rather increases subsequent entropy
	Dir { seed: Seed },
}

impl LockedEntry {
	pub fn hash(&self) -> hmac::Digest {
		use LockedEntry::*;

		let bytes = match self {
			File { info } => [&info.key_iv.as_bytes(), info.ext.as_bytes()].concat(),
			Dir { seed } => seed.bytes.to_vec(),
		};

		let sha = Sha256::digest(&bytes);

		hmac::Digest(sha.into())
	}
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub(crate) struct LockedNode {
	pub(crate) id: Uid,
	pub(crate) parent_id: Uid,
	pub(crate) content: Encrypted,
	pub(crate) dirty: bool,
}

#[derive(Serialize, Deserialize)]
struct LockedContent {
	created_at: u64,
	name: String,
	created_by: identity::Public,
	// keep a chain between sig and last_edited sig?
	// TODO: intorduce a list of edits?
	// edit: { editerd_by, edited_at, sig }
	sig: ed25519::Signature,
	entry: LockedEntry,
}

pub(crate) struct NewNodeReq {
	pub(crate) node: Node,
	pub(crate) locked_node: LockedNode,
}

impl LockedContent {
	fn try_from_encrypted(ct: &[u8], aes: Aes, id: Uid, parent_id: Uid) -> Result<Self, Error> {
		let pt = aes.decrypt(ct).map_err(|_| Error::BadOperation)?;
		let content: LockedContent =
			serde_json::from_slice(&pt).map_err(|_| Error::BadOperation)?;

		if content.created_by.verify(
			&content.sig,
			&Self::ctx_to_sign(
				content.created_at,
				&content.name,
				&content.created_by,
				&content.entry,
				id,
				parent_id,
			),
		) {
			Ok(content)
		} else {
			Err(Error::ForgedSig)
		}
	}

	fn ctx_to_sign(
		created_at: u64,
		name: &str,
		created_by: &identity::Public,
		entry: &LockedEntry,
		id: Uid,
		parent_id: Uid,
	) -> Vec<u8> {
		[
			created_at.to_be_bytes().as_slice(),
			name.as_bytes(),
			created_by.hash().as_bytes(),
			entry.hash().as_bytes(),
			id.as_bytes().as_slice(),
			parent_id.as_bytes().as_slice(),
		]
		.concat()
	}
}

#[derive(Clone, PartialEq, Debug)]
pub(crate) struct Node {
	pub(crate) id: Uid,
	pub(crate) parent_id: Uid,
	pub created_at: u64,
	pub name: String,
	pub(crate) entry: Entry,
	pub dirty: bool,
	pub(crate) created_by: identity::Public,
	// last_edited_by
}

#[derive(Clone, Debug)]
pub(crate) enum Entry {
	File { info: FileInfo },
	Dir { seed: Seed, children: Vec<Node> },
}

impl PartialEq for Entry {
	fn eq(&self, other: &Self) -> bool {
		match (self, other) {
			(Self::File { info: l_info }, Self::File { info: r_info }) => l_info == r_info,
			(
				Self::Dir {
					seed: l_seed,
					children: l_children,
				},
				Self::Dir {
					seed: r_seed,
					children: r_children,
				},
			) => {
				l_seed == r_seed
					&& l_children.len() == r_children.len()
					&& l_children.iter().all(|e| r_children.contains(e))
			}
			_ => false,
		}
	}
}

// Use to share access to a particular file/dir and paste to aes_from_node_seed_and_salt
fn seed_from_parent_for_node(parent: &Seed, id: Uid) -> Seed {
	Seed {
		bytes: Hkdf::from_ikm(&[parent.bytes.as_slice(), &id.as_bytes()].concat())
			.expand_no_info::<{ seeds::SEED_SIZE }>(),
	}
}

fn aes_from_parent_seed_for_node(seed: &Seed, id: Uid, salt: &Salt) -> Aes {
	let node_seed = seed_from_parent_for_node(seed, id);

	aes_from_node_seed(&node_seed, salt)
}

// use this to encrypt/decrypt nodes
fn aes_from_node_seed(seed: &Seed, salt: &Salt) -> Aes {
	let key_iv = Hkdf::from_ikm(&[seed.bytes.as_slice(), &salt.bytes].concat())
		.expand_no_info::<{ aes_gcm::Key::SIZE + aes_gcm::Iv::SIZE }>();

	aes_gcm::Aes::from(&key_iv)
}

impl Node {
	fn encrypt_with_parent_seed(
		node: &Node,
		parent: &Seed,
		sign_by: &identity::Private,
	) -> LockedNode {
		let seed = seed_from_parent_for_node(parent, node.id);

		Self::encrypt(node, &seed, sign_by)
	}

	fn encrypt(node: &Node, node_seed: &Seed, sign_by: &identity::Private) -> LockedNode {
		let entry = match &node.entry {
			Entry::File { info } => LockedEntry::File { info: info.clone() },
			Entry::Dir { seed, .. } => LockedEntry::Dir { seed: seed.clone() },
		};
		let to_sign = LockedContent::ctx_to_sign(
			node.created_at,
			&node.name,
			&node.created_by,
			&entry,
			node.id,
			node.parent_id,
		);
		let sig = sign_by.sign(&to_sign);
		let locked_content = LockedContent {
			created_at: node.created_at,
			name: node.name.clone(),
			entry,
			created_by: node.created_by.clone(),
			sig,
		};
		let salt = Salt::generate();
		let aes = aes_from_node_seed(node_seed, &salt);
		let ct = aes.encrypt_serializable(&locked_content);
		let encrypted = Encrypted { ct, salt };
		// something is failing to serialize here

		LockedNode {
			id: node.id,
			parent_id: node.parent_id,
			content: encrypted,
			dirty: false,
		}
	}
}

#[derive(PartialEq, Debug, Clone)]
pub(crate) struct FileSystem {
	// a user can have multiple top-level shares belonging to different
	// subtrees, therefore more than one root is possible
	roots: Vec<Node>,
	// a cache of shares
	cached_seeds: Seeds,
}

pub(crate) const NO_PARENT_ID: u64 = u64::MAX;

#[cfg(target_arch = "wasm32")]
fn now() -> u64 {
	use js_sys::Date;
	Date::now() as u64
}

#[cfg(not(target_arch = "wasm32"))]
fn now() -> u64 {
	use std::time::{SystemTime, UNIX_EPOCH};
	let duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

	duration.as_secs() * 1000 + duration.subsec_millis() as u64
}

impl FileSystem {
	// returns FileSystem { root_node } & its json
	pub fn new(fs_seed: &Seed, owner: &identity::Identity) -> (Self, LockedNode) {
		let id = Uid::new(ROOT_ID);
		let parent_id = Uid::new(NO_PARENT_ID);
		let created_at = now();
		let name = "/".to_string();
		let seed = Seed::generate();
		let node = Node {
			id,
			parent_id,
			created_at,
			name,
			entry: Entry::Dir {
				seed,
				children: Vec::new(),
			},
			created_by: owner.public().clone(),
			dirty: false,
		};
		let locked_root = Node::encrypt(&node, fs_seed, owner.private());
		let cached_seeds = vec![(id, fs_seed.clone())].into_iter().collect();

		(
			Self {
				roots: vec![node],
				cached_seeds,
			},
			locked_root,
		)
	}

	// TODO: for god, remember to pass one share { root_id: seed } manually
	pub fn from_locked_nodes(locked_nodes: &[LockedNode], bundles: &Seeds) -> FileSystem {
		let (mut nodes, branches, roots) = Self::parse_locked(locked_nodes, bundles);

		FileSystem {
			roots: Self::build_hierarchy(&mut nodes, &branches, &roots),
			cached_seeds: bundles.clone(),
		}
	}

	// a universal method for files as well?
	// how about removeal?
	pub fn add_or_update_subtree(
		&mut self,
		locked_nodes: &[LockedNode],
		parent_id: Uid,
	) -> Result<(), Error> {
		if let Some(parent) = self.node_by_id_mut(parent_id) {
			parent.dirty = false;

			if let Entry::Dir {
				ref seed,
				ref mut children,
			} = parent.entry
			{
				let mut node_map: HashMap<Uid, Node> = HashMap::new();
				let mut locked_node_map: HashMap<Uid, &LockedNode> = HashMap::new();
				let mut branches: HashMap<Uid, Vec<Uid>> = HashMap::new();

				// put each node to a branch, if possible
				for locked_node in locked_nodes {
					if locked_nodes.iter().any(|ln| ln.id == locked_node.parent_id)
						|| locked_node.parent_id == parent_id
					{
						branches
							.entry(locked_node.parent_id)
							.or_default()
							.push(locked_node.id);
					}

					locked_node_map.insert(locked_node.id, locked_node);
				}

				let roots = branches.get(&parent_id).unwrap_or(&Vec::new()).clone();

				for node_id in &roots {
					if let Some(locked_node) = locked_node_map.remove(&node_id) {
						let encrypted = &locked_node.content;
						let aes =
							aes_from_parent_seed_for_node(seed, locked_node.id, &encrypted.salt);
						if let Ok(content) = LockedContent::try_from_encrypted(
							&encrypted.ct,
							aes,
							locked_node.id,
							locked_node.parent_id,
						) {
							let node = Node {
								id: locked_node.id,
								parent_id: locked_node.parent_id,
								created_at: content.created_at,
								name: content.name,
								entry: match content.entry {
									LockedEntry::File { info } => Entry::File { info },
									LockedEntry::Dir { seed } => Entry::Dir {
										seed,
										children: vec![],
									},
								},
								dirty: locked_node.dirty,
								created_by: content.created_by,
							};
							node_map.insert(node.id, node);
						}
					}
				}

				let mut to_process: Vec<Uid> = node_map.keys().cloned().collect();

				while let Some(id) = to_process.pop() {
					let mut new_nodes = Vec::new();

					if let Some(node) = node_map.get(&id) {
						if let Entry::Dir { seed, .. } = &node.entry {
							if let Some(child_ids) = branches.get(&id) {
								for child_id in child_ids {
									if let Some(locked_node) = locked_node_map.get(&child_id) {
										let encrypted = &locked_node.content;
										let aes = aes_from_parent_seed_for_node(
											seed,
											*child_id,
											&encrypted.salt,
										);

										if let Ok(content) = LockedContent::try_from_encrypted(
											&encrypted.ct,
											aes,
											locked_node.id,
											locked_node.parent_id,
										) {
											let child_node = Node {
												id: locked_node.id,
												parent_id: locked_node.parent_id,
												created_at: content.created_at,
												name: content.name.clone(),
												entry: match content.entry {
													LockedEntry::File { info } => {
														Entry::File { info }
													}
													LockedEntry::Dir { seed } => Entry::Dir {
														seed,
														children: vec![],
													},
												},
												dirty: locked_node.dirty,
												created_by: content.created_by,
											};

											new_nodes.push((child_id, child_node));
											to_process.push(*child_id);
										}
									}
								}
							}
						}
					}

					for (child_id, child_node) in new_nodes {
						locked_node_map.remove(&child_id);
						node_map.insert(*child_id, child_node);
					}
				}

				*children = Self::build_hierarchy(&mut node_map, &branches, &roots);
				// TODO: move dirty from Node to Entry::Dir and set to false here

				Ok(())
			} else {
				Err(Error::BadOperation)
			}
		} else {
			Err(Error::NotFound)
		}
	}

	// returns (nodes, branches, roots)
	fn parse_locked(
		locked_nodes: &[LockedNode],
		bundles: &Seeds,
	) -> (HashMap<Uid, Node>, HashMap<Uid, Vec<Uid>>, Vec<Uid>) {
		// rebuild from self.nodes? – rathe rnot
		let mut node_map: HashMap<Uid, Node> = HashMap::new();
		let mut locked_node_map: HashMap<Uid, &LockedNode> = HashMap::new();
		let mut branches: HashMap<Uid, Vec<Uid>> = HashMap::new();
		let mut roots = Vec::new();

		// put each node to a branch, if possible
		for locked_node in locked_nodes {
			if locked_nodes.iter().any(|ln| ln.id == locked_node.parent_id) {
				branches
					.entry(locked_node.parent_id)
					.or_default()
					.push(locked_node.id);
			}

			locked_node_map.insert(locked_node.id, locked_node);
		}

		// won't work when updating a subroot; need a parent's seed to continue
		// redundant bundles should probably be filtered form out here
		for (node_id, seed) in bundles {
			if let Some(locked_node) = locked_node_map.remove(node_id) {
				let encrypted = &locked_node.content;
				let aes = aes_from_node_seed(seed, &encrypted.salt);

				if let Ok(content) = LockedContent::try_from_encrypted(
					&encrypted.ct,
					aes,
					locked_node.id,
					locked_node.parent_id,
				) {
					let node = Node {
						id: locked_node.id,
						parent_id: locked_node.parent_id,
						created_at: content.created_at,
						name: content.name,
						entry: match content.entry {
							LockedEntry::File { info } => Entry::File { info },
							LockedEntry::Dir { seed } => Entry::Dir {
								seed,
								children: vec![],
							},
						},
						dirty: locked_node.dirty,
						created_by: content.created_by,
					};
					node_map.insert(node.id, node);
				}
			}
		}

		let mut to_process: Vec<Uid> = node_map.keys().cloned().collect();

		while let Some(id) = to_process.pop() {
			let mut new_nodes = Vec::new();

			if let Some(node) = node_map.get(&id) {
				if let Entry::Dir { seed, .. } = &node.entry {
					if let Some(child_ids) = branches.get(&id) {
						for child_id in child_ids {
							if let Some(locked_node) = locked_node_map.get(&child_id) {
								let encrypted = &locked_node.content;
								let aes =
									aes_from_parent_seed_for_node(seed, *child_id, &encrypted.salt);

								if let Ok(content) = LockedContent::try_from_encrypted(
									&encrypted.ct,
									aes,
									locked_node.id,
									locked_node.parent_id,
								) {
									let child_node = Node {
										id: locked_node.id,
										parent_id: locked_node.parent_id,
										created_at: content.created_at,
										name: content.name.clone(),
										entry: match content.entry {
											LockedEntry::File { info } => Entry::File { info },
											LockedEntry::Dir { seed } => Entry::Dir {
												seed,
												children: vec![],
											},
										},
										dirty: locked_node.dirty,
										created_by: content.created_by,
									};

									new_nodes.push((child_id, child_node));
									to_process.push(*child_id);
								}
							}
						}
					}
				}
			}

			for (child_id, child_node) in new_nodes {
				locked_node_map.remove(&child_id);
				node_map.insert(*child_id, child_node);
			}
		}

		for (id, node) in &node_map {
			if !node_map.contains_key(&node.parent_id) {
				roots.push(*id);
			}
		}

		// (node_map, branches, bundles.keys().cloned().collect()
		(node_map, branches, roots)
	}

	fn build_hierarchy(
		nodes: &mut HashMap<Uid, Node>,
		branches: &HashMap<Uid, Vec<Uid>>,
		roots: &[Uid],
	) -> Vec<Node> {
		fn add_children_to_node(
			node: &mut Node,
			nodes: &mut HashMap<Uid, Node>,
			branches: &HashMap<Uid, Vec<Uid>>,
		) {
			if let Entry::Dir { children, .. } = &mut node.entry {
				if let Some(children_ids) = branches.get(&node.id) {
					for &child_id in children_ids {
						if let Some(mut child) = nodes.remove(&child_id) {
							add_children_to_node(&mut child, nodes, branches);
							children.push(child);
						}
					}
				}
			}
		}

		let mut hierarchy = Vec::new();

		// FIXME: this piece is not exactly correct: it may still build [grandchild,
		// child, parent, grandparent], if redundant bundles have been supplied
		for &root_id in roots {
			if let Some(mut root) = nodes.remove(&root_id) {
				add_children_to_node(&mut root, nodes, branches);
				hierarchy.push(root);
			}
		}

		hierarchy
	}

	pub fn ls_root(&self) -> Vec<&Node> {
		if let Some(children) = self.roots.iter().find_map(|n| {
			// if we have a root, then display its children
			if n.id == ROOT_ID {
				if let Entry::Dir { ref children, .. } = n.entry {
					Some(children.iter().collect())
				} else {
					None
				}
			} else {
				None
			}
		}) {
			children
		} else {
			// otherwise we have a bunch of detached nodes – display them instead
			self.roots.iter().collect()
		}
	}

	pub fn node_by_id(&self, id: Uid) -> Option<&Node> {
		self.roots.iter().find_map(|node| self.dfs(node, id))
	}

	fn dfs<'a>(&self, node: &'a Node, id: Uid) -> Option<&'a Node> {
		if node.id == id {
			return Some(node);
		}

		if let Entry::Dir { children, .. } = &node.entry {
			for child in children {
				if let Some(found) = self.dfs(child, id) {
					return Some(found);
				}
			}
		}
		None
	}

	pub fn node_by_id_mut(&mut self, id: Uid) -> Option<&mut Node> {
		let mut stack: Vec<&mut Node> = self.roots.iter_mut().collect();

		while let Some(node) = stack.pop() {
			if node.id == id {
				return Some(node);
			}

			if let Entry::Dir { children, .. } = &mut node.entry {
				for child in children {
					stack.push(child);
				}
			}
		}

		None
	}

	pub fn ls_dir(&self, id: Uid) -> Result<Vec<&Node>, Error> {
		if let Some(node) = self.node_by_id(id) {
			if let Entry::Dir { ref children, .. } = node.entry {
				Ok(children.iter().collect())
			} else {
				Err(Error::BadOperation)
			}
		} else {
			Err(Error::NotFound)
		}
	}

	// mkdir and immediately apply its transaction
	pub fn mkdir_mut(
		&mut self,
		parent_id: Uid,
		name: &str,
		owner: &identity::Identity,
	) -> Result<(Uid, LockedNode), Error> {
		let NewNodeReq { node, locked_node } = self.mkdir(parent_id, name, owner)?;
		let id = self.insert_node(node)?;

		Ok((id, locked_node))
	}

	pub fn mkdir(
		&self,
		parent_id: Uid,
		name: &str,
		owner: &identity::Identity,
	) -> Result<NewNodeReq, Error> {
		if let Some(node) = self.node_by_id(parent_id) {
			if let Entry::Dir {
				children: _,
				seed: ref parent_seed,
			} = node.entry
			{
				let id = Uid::generate();
				let new_node = Node {
					id,
					parent_id,
					created_at: now(),
					name: name.to_string(),
					entry: Entry::Dir {
						seed: Seed::generate(),
						children: vec![],
					},
					dirty: false,
					created_by: owner.public().clone(),
				};
				let locked_node =
					Node::encrypt_with_parent_seed(&new_node, parent_seed, owner.private());

				Ok(NewNodeReq {
					node: new_node,
					locked_node,
				})
			} else {
				Err(Error::BadOperation)
			}
		} else {
			Err(Error::NoAccess)
		}
	}

	pub fn insert_node(&mut self, node: Node) -> Result<Uid, Error> {
		if let Some(parent) = self.node_by_id_mut(node.parent_id) {
			if let Entry::Dir {
				ref mut children,
				seed: _,
			} = parent.entry
			{
				let id = node.id;

				children.push(node);

				Ok(id)
			} else {
				Err(Error::BadOperation)
			}
		} else {
			Err(Error::NotFound)
		}
	}

	pub fn delete_node(&mut self, id: Uid) -> Result<(), Error> {
		if let Some(node) = self.node_by_id(id) {
			if let Some(parent) = self.node_by_id_mut(node.parent_id) {
				if let Entry::Dir {
					ref mut children,
					seed: _,
				} = parent.entry
				{
					children.retain(|n| n.id != id);

					return Ok(());
				}
			} else {
				// remove from the roots
				self.roots.retain(|n| n.id != id);
			}
		}

		return Err(Error::NotFound);
	}

	// touch and immediately apply its transaction
	// TODO: the backend should create a PendingUpload(id); when uploaded /save/id should be called
	pub fn touch_mut(
		&mut self,
		parent_id: Uid,
		size: u32,
		name: &str,
		ext: &str,
		owner: &identity::Identity,
	) -> Result<(Uid, LockedNode), Error> {
		let NewNodeReq { node, locked_node } = self.touch(parent_id, size, name, ext, owner)?;
		let id = self.insert_node(node)?;

		Ok((id, locked_node))
	}

	pub fn touch(
		&self,
		parent_id: Uid,
		size: u32,
		name: &str,
		ext: &str,
		owner: &identity::Identity,
	) -> Result<NewNodeReq, Error> {
		if let Some(node) = self.node_by_id(parent_id) {
			if let Entry::Dir {
				children: _,
				seed: ref parent_seed,
			} = node.entry
			{
				let id = Uid::generate();
				let new_node = Node {
					id,
					parent_id,
					created_at: now(),
					name: name.to_string(),
					entry: Entry::File {
						info: FileInfo {
							size,
							key_iv: Aes::new(),
							ext: ext.to_string(),
						},
					},
					dirty: false,
					created_by: owner.public().clone(),
				};
				let locked_node =
					Node::encrypt_with_parent_seed(&new_node, parent_seed, owner.private());

				Ok(NewNodeReq {
					node: new_node,
					locked_node,
				})
			} else {
				Err(Error::BadOperation)
			}
		} else {
			Err(Error::NoAccess)
		}
	}

	pub fn share_node(&mut self, id: Uid) -> Result<Seed, Error> {
		if let Some(seed) = self.cached_seeds.get(&id) {
			Ok(seed.clone())
		} else if let Some(node) = self.node_by_id(id) {
			if let Some(parent) = self.node_by_id(node.parent_id) {
				if let Entry::Dir { ref seed, .. } = parent.entry {
					let share = seed_from_parent_for_node(seed, id);

					self.cached_seeds.insert(id, share.clone());

					Ok(share)
				} else {
					Err(Error::BadOperation)
				}
			} else {
				// we'll probably never get here
				Err(Error::NoAccess)
			}
		} else {
			Err(Error::NotFound)
		}
	}
}

#[cfg(test)]
mod tests {
	use identity::Identity;

	use super::*;

	fn is_dir(fs: &FileSystem, id: Uid, name: &str, parent: Uid) -> bool {
		fs.node_by_id(id).map_or(false, |n| {
			matches!(n.entry, Entry::Dir { .. }) && n.name == name && n.parent_id == parent
		})
	}

	fn is_file(fs: &FileSystem, id: Uid, name: &str, parent: Uid) -> bool {
		fs.node_by_id(id).map_or(false, |n| {
			matches!(n.entry, Entry::File { .. }) && n.name == name && n.parent_id == parent
		})
	}

	#[test]
	fn test_create_mkdir_touch() {
		let god = Identity::generate(Uid::new(0));
		let seed = Seed::generate();
		let (mut fs, _) = FileSystem::new(&seed, &god);

		let _1 = fs.mkdir_mut(Uid::new(ROOT_ID), "1", &god).unwrap();
		let _1_1 = fs.mkdir_mut(_1.0, "1_1", &god).unwrap();
		let _1_2 = fs.mkdir_mut(_1.0, "1_2", &god).unwrap();
		let _1_1_1 = fs.mkdir_mut(_1_1.0, "1_1_1", &god).unwrap();
		let _1_1_1_atxt = fs.touch_mut(_1_1_1.0, 0, "a", "txt", &god).unwrap();

		assert_eq!(fs.ls_dir(Uid::new(ROOT_ID)).unwrap().len(), 1);
		assert_eq!(fs.ls_dir(_1.0).unwrap().len(), 2);
		assert_eq!(fs.ls_dir(_1_1.0).unwrap().len(), 1);
		assert_eq!(fs.ls_dir(_1_2.0).unwrap().len(), 0);
		assert_eq!(fs.ls_dir(_1_1_1.0).unwrap().len(), 1);
		assert_eq!(fs.ls_dir(_1_1_1_atxt.0), Err(Error::BadOperation));

		assert!(is_dir(&fs, Uid::new(ROOT_ID), "/", Uid::new(NO_PARENT_ID)));
		assert!(is_dir(&fs, _1.0, "1", Uid::new(ROOT_ID)));
		assert!(is_dir(&fs, _1_1.0, "1_1", _1.0));
		assert!(is_dir(&fs, _1_2.0, "1_2", _1.0));
		assert!(is_dir(&fs, _1_1_1.0, "1_1_1", _1_1.0));
		assert!(is_file(&fs, _1_1_1_atxt.0, "a", _1_1_1.0));
	}

	#[test]
	fn test_from_locked_nodes_for_root() {
		let seed = Seed::generate();
		let god = Identity::generate(Uid::new(0));
		let (mut fs, root) = FileSystem::new(&seed, &god);

		let _1 = fs.mkdir_mut(Uid::new(ROOT_ID), "1", &god).unwrap();
		let _1_1 = fs.mkdir_mut(_1.0, "1_1", &god).unwrap();
		let _1_2 = fs.mkdir_mut(_1.0, "1_2", &god).unwrap();
		let _1_1_1 = fs.mkdir_mut(_1_1.0, "1_1_1", &god).unwrap();
		let _1_1_1_atxt = fs.touch_mut(_1_1_1.0, 0, "a", "txt", &god).unwrap();

		let locked_nodes = vec![root, _1.1, _1_1.1, _1_2.1, _1_1_1.1, _1_1_1_atxt.1];

		let bundles = vec![(Uid::new(ROOT_ID), seed.clone())]
			.into_iter()
			.collect();
		let restored = FileSystem::from_locked_nodes(&locked_nodes, &bundles);

		assert_eq!(fs, restored);
	}

	fn eval_share(fs: &mut FileSystem, id: Uid, parent_id: Uid) -> bool {
		let share = fs.share_node(id).unwrap();

		matches!(fs.node_by_id(parent_id).unwrap().entry, Entry::Dir { ref seed, .. } if seed_from_parent_for_node(seed, id) == share)
	}

	#[test]
	fn test_share_individual_nodes() {
		let seed = Seed::generate();
		let god = Identity::generate(Uid::new(0));
		let (mut fs, _) = FileSystem::new(&seed, &god);

		let _1 = fs.mkdir_mut(Uid::new(ROOT_ID), "1", &god).unwrap();
		let _1_1 = fs.mkdir_mut(_1.0, "1_1", &god).unwrap();
		let _1_2 = fs.mkdir_mut(_1.0, "1_2", &god).unwrap();
		let _1_1_1 = fs.mkdir_mut(_1_1.0, "1_1_1", &god).unwrap();
		let _1_1_1_atxt = fs.touch_mut(_1_1_1.0, 0, "a", "txt", &god).unwrap();

		assert!(eval_share(&mut fs, _1_1_1_atxt.0, _1_1_1.0));
		assert!(eval_share(&mut fs, _1_1_1.0, _1_1.0));
		assert!(eval_share(&mut fs, _1_1.0, _1.0));
		assert!(eval_share(&mut fs, _1_2.0, _1.0));
		assert!(eval_share(&mut fs, _1.0, Uid::new(ROOT_ID)));
		assert_eq!(fs.share_node(Uid::new(ROOT_ID)), Ok(seed));

		assert!(!eval_share(&mut fs, _1_1_1_atxt.0, _1.0));
		assert!(!eval_share(&mut fs, _1_1_1.0, _1_2.0));
		assert!(!eval_share(&mut fs, _1_1.0, Uid::new(ROOT_ID)));
		assert!(!eval_share(&mut fs, _1_2.0, _1_2.0));
		assert!(!eval_share(&mut fs, _1.0, _1_1_1.0));
	}

	#[test]
	fn test_share_a_file() {
		let seed = Seed::generate();
		let god = Identity::generate(Uid::new(0));
		let (mut fs, root) = FileSystem::new(&seed, &god);

		let _1 = fs.mkdir_mut(Uid::new(ROOT_ID), "1", &god).unwrap();
		let _1_1 = fs.mkdir_mut(_1.0, "1_1", &god).unwrap();
		let _1_2 = fs.mkdir_mut(_1.0, "1_2", &god).unwrap();
		let _1_1_1 = fs.mkdir_mut(_1_1.0, "1_1_1", &god).unwrap();
		let _1_1_1_atxt = fs.touch_mut(_1_1_1.0, 0, "a", "txt", &god).unwrap();

		let share = fs.share_node(_1_1_1_atxt.0).unwrap();
		let locked_nodes = vec![root, _1_1_1_atxt.1, _1.1, _1_1_1.1, _1_2.1, _1_1.1];
		let bundles = vec![(_1_1_1_atxt.0, share)].into_iter().collect();

		let fs_partial = FileSystem::from_locked_nodes(&locked_nodes, &bundles);

		assert!(is_file(&fs_partial, _1_1_1_atxt.0, "a", _1_1_1.0));
		assert_eq!(
			fs_partial.ls_root(),
			vec![fs_partial.node_by_id(_1_1_1_atxt.0).unwrap()]
		);
	}

	#[test]
	fn test_share_several_files_detached_as_roots() {
		let seed = Seed::generate();
		let god = Identity::generate(Uid::new(0));
		let (mut fs, root) = FileSystem::new(&seed, &god);

		let _1 = fs.mkdir_mut(Uid::new(ROOT_ID), "1", &god).unwrap();
		let _1_1 = fs.mkdir_mut(_1.0, "1_1", &god).unwrap();
		let _1_1_ctxt = fs.touch_mut(_1_1.0, 0, "c", "txt", &god).unwrap();
		let _1_2 = fs.mkdir_mut(_1.0, "1_2", &god).unwrap();
		let _1_1_1 = fs.mkdir_mut(_1_1.0, "1_1_1", &god).unwrap();
		let _1_1_1_atxt = fs.touch_mut(_1_1_1.0, 0, "a", "txt", &god).unwrap();
		let _1_1_1_btxt = fs.touch_mut(_1_1_1.0, 0, "b", "txt", &god).unwrap();

		let _1_1_1_a_share = fs.share_node(_1_1_1_atxt.0).unwrap();
		let _1_1_1_b_share = fs.share_node(_1_1_1_btxt.0).unwrap();
		let _1_1_a_share = fs.share_node(_1_1_ctxt.0).unwrap();

		let locked_nodes = vec![
			root,
			_1.1,
			_1_2.1,
			_1_1.1,
			_1_1_1_atxt.1,
			_1_1_1.1,
			_1_1_1_btxt.1,
			_1_1_ctxt.1,
		];
		let bundles = vec![
			(_1_1_1_atxt.0, _1_1_1_a_share),
			(_1_1_ctxt.0, _1_1_a_share),
			(_1_1_1_btxt.0, _1_1_1_b_share),
		]
		.into_iter()
		.collect();

		let fs_partial = FileSystem::from_locked_nodes(&locked_nodes, &bundles);

		assert!(is_file(&fs_partial, _1_1_1_atxt.0, "a", _1_1_1.0));
		assert!(is_file(&fs_partial, _1_1_1_btxt.0, "b", _1_1_1.0));
		assert!(is_file(&fs_partial, _1_1_ctxt.0, "c", _1_1.0));
		assert!(fs_partial.ls_root().iter().map(|n| n.id).all(|id| [
			_1_1_1_atxt.0,
			_1_1_1_btxt.0,
			_1_1_ctxt.0
		]
		.contains(&id)));
	}

	#[test]
	fn test_share_several_dirs_detached_as_roots() {
		let seed = Seed::generate();
		let god = Identity::generate(Uid::new(0));
		let (mut fs, root) = FileSystem::new(&seed, &god);

		let _1 = fs.mkdir_mut(Uid::new(ROOT_ID), "1", &god).unwrap();
		let _1_1 = fs.mkdir_mut(_1.0, "1_1", &god).unwrap();
		let _1_1_atxt = fs.touch_mut(_1_1.0, 0, "a1", "txt", &god).unwrap();
		let _1_2 = fs.mkdir_mut(_1.0, "1_2", &god).unwrap();
		let _1_1_1 = fs.mkdir_mut(_1_1.0, "1_1_1", &god).unwrap();
		let _1_1_1_atxt = fs.touch_mut(_1_1_1.0, 0, "a", "txt", &god).unwrap();
		let _1_1_1_btxt = fs.touch_mut(_1_1_1.0, 0, "b", "txt", &god).unwrap();

		let _1_1_1_share = fs.share_node(_1_1_1.0).unwrap();
		let _1_2_share = fs.share_node(_1_2.0).unwrap();

		let locked_nodes = vec![
			root,
			_1.1,
			_1_2.1,
			_1_1.1,
			_1_1_1_atxt.1,
			_1_1_1.1,
			_1_1_1_btxt.1,
			_1_1_atxt.1,
		];
		let bundles = vec![(_1_1_1.0, _1_1_1_share), (_1_2.0, _1_2_share)]
			.into_iter()
			.collect();

		let fs_partial = FileSystem::from_locked_nodes(&locked_nodes, &bundles);

		assert!(is_dir(&fs_partial, _1_1_1.0, "1_1_1", _1_1.0));
		assert!(is_dir(&fs_partial, _1_2.0, "1_2", _1.0));
		assert!(fs_partial
			.ls_root()
			.iter()
			.map(|n| n.id)
			.all(|id| [_1_1_1.0, _1_2.0].contains(&id)));
	}

	#[test]
	fn test_share_mixed() {
		let god = Identity::generate(Uid::new(0));
		let seed = Seed::generate();
		let (mut fs, root) = FileSystem::new(&seed, &god);

		let _1 = fs.mkdir_mut(Uid::new(ROOT_ID), "1", &god).unwrap();
		let _1_1 = fs.mkdir_mut(_1.0, "1_1", &god).unwrap();
		let _1_1_atxt = fs.touch_mut(_1_1.0, 0, "a1", "txt", &god).unwrap();
		let _1_2 = fs.mkdir_mut(_1.0, "1_2", &god).unwrap();
		let _1_1_1 = fs.mkdir_mut(_1_1.0, "1_1_1", &god).unwrap();
		let _1_1_1_atxt = fs.touch_mut(_1_1_1.0, 0, "a", "txt", &god).unwrap();
		let _1_1_1_btxt = fs.touch_mut(_1_1_1.0, 0, "b", "txt", &god).unwrap();
		let _1_1_1_1 = fs.mkdir_mut(_1_1_1.0, "1_1_1_1", &god).unwrap();

		let _1_1_1_a_share = fs.share_node(_1_1_1_atxt.0).unwrap();
		let _1_1_1_b_share = fs.share_node(_1_1_1_btxt.0).unwrap();
		let _1_2_share = fs.share_node(_1_2.0).unwrap();

		let locked_nodes = vec![
			root,
			_1.1,
			_1_2.1,
			_1_1.1,
			_1_1_1_1.1,
			_1_1_1_atxt.1,
			_1_1_1.1,
			_1_1_1_btxt.1,
			_1_1_atxt.1,
		];
		let bundles = vec![
			(_1_1_1_atxt.0, _1_1_1_a_share),
			(_1_1_1_btxt.0, _1_1_1_b_share),
			(_1_2.0, _1_2_share),
		]
		.into_iter()
		.collect();

		let fs_partial = FileSystem::from_locked_nodes(&locked_nodes, &bundles);

		assert!(is_dir(&fs_partial, _1_2.0, "1_2", _1.0));
		assert!(is_file(&fs_partial, _1_1_1_atxt.0, "a", _1_1_1.0));
		assert!(is_file(&fs_partial, _1_1_1_btxt.0, "b", _1_1_1.0));
		assert!(fs_partial.ls_root().iter().map(|n| n.id).all(|id| [
			_1_1_1_atxt.0,
			_1_1_1_btxt.0,
			_1_2.0
		]
		.contains(&id)));
	}

	#[test]
	fn test_errors() {
		let seed = Seed::generate();
		let god = Identity::generate(Uid::new(0));
		let (mut fs, root) = FileSystem::new(&seed, &god);

		let _1 = fs.mkdir_mut(Uid::new(ROOT_ID), "1", &god).unwrap();
		let _1_1 = fs.mkdir_mut(_1.0, "1_1", &god).unwrap();
		let _1_1_atxt = fs.touch_mut(_1_1.0, 0, "a1", "txt", &god).unwrap();
		let _1_2 = fs.mkdir_mut(_1.0, "1_2", &god).unwrap();
		let _1_1_1 = fs.mkdir_mut(_1_1.0, "1_1_1", &god).unwrap();
		let _1_1_1_atxt = fs.touch_mut(_1_1_1.0, 0, "a", "txt", &god).unwrap();
		let _1_1_1_btxt = fs.touch_mut(_1_1_1.0, 0, "b", "txt", &god).unwrap();
		let _1_1_1_1 = fs.mkdir_mut(_1_1_1.0, "1_1_1_1", &god).unwrap();

		let _1_1_1_a_share = fs.share_node(_1_1_1_atxt.0).unwrap();
		let _1_1_1_b_share = fs.share_node(_1_1_1_btxt.0).unwrap();
		let _1_2_share = fs.share_node(_1_2.0).unwrap();

		assert_eq!(fs.share_node(Uid::new(9999999)), Err(Error::NotFound));
		assert_eq!(
			fs.mkdir_mut(_1_1_1_atxt.0, "bad", &god),
			Err(Error::BadOperation)
		);

		let locked_nodes = vec![
			root,
			_1.1,
			_1_2.1,
			_1_1.1,
			_1_1_1_1.1,
			_1_1_1_atxt.1,
			_1_1_1.1,
			_1_1_1_btxt.1,
			_1_1_atxt.1,
		];
		let bundles = vec![
			(_1_1_1_atxt.0, _1_1_1_a_share.clone()),
			(_1_1_1_btxt.0, _1_1_1_b_share.clone()),
			(_1_2.0, _1_2_share.clone()),
		]
		.into_iter()
		.collect();

		let mut fs_partial = FileSystem::from_locked_nodes(&locked_nodes, &bundles);

		assert!(is_dir(&fs_partial, _1_2.0, "1_2", _1.0));
		assert!(is_file(&fs_partial, _1_1_1_atxt.0, "a", _1_1_1.0));
		assert!(is_file(&fs_partial, _1_1_1_btxt.0, "b", _1_1_1.0));
		assert!(fs_partial.ls_root().iter().map(|n| n.id).all(|id| [
			_1_1_1_atxt.0,
			_1_1_1_btxt.0,
			_1_2.0
		]
		.contains(&id)));

		// _1 is not in the hierarchy
		assert_eq!(fs_partial.share_node(_1.0), Err(Error::NotFound));
		// these are is in the cache, so can be shared
		assert_eq!(fs_partial.share_node(_1_2.0), Ok(_1_2_share));
		assert_eq!(fs_partial.share_node(_1_1_1_atxt.0), Ok(_1_1_1_a_share));
		assert_eq!(fs_partial.share_node(_1_1_1_btxt.0), Ok(_1_1_1_b_share));
	}

	#[test]
	fn test_update_node_with_empty_children() {
		let seed = Seed::generate();
		let god = Identity::generate(Uid::new(0));
		let (mut fs, _) = FileSystem::new(&seed, &god);

		let _1 = fs.mkdir_mut(Uid::new(ROOT_ID), "1", &god).unwrap();
		let _1_1 = fs.mkdir_mut(_1.0, "1_1", &god).unwrap();
		let _1_1_atxt = fs.touch_mut(_1_1.0, 0, "a1", "txt", &god).unwrap();
		let _1_2 = fs.mkdir_mut(_1.0, "1_2", &god).unwrap();
		let _1_1_1 = fs.mkdir_mut(_1_1.0, "1_1_1", &god).unwrap();
		let _1_1_1_atxt = fs.touch_mut(_1_1_1.0, 0, "a", "txt", &god).unwrap();
		let _1_1_1_btxt = fs.touch_mut(_1_1_1.0, 0, "b", "txt", &god).unwrap();
		let _1_1_1_1 = fs.mkdir_mut(_1_1_1.0, "1_1_1_1", &god).unwrap();

		let mut fs_copy = fs.clone();
		assert_eq!(fs, fs_copy);

		assert_eq!(fs_copy.ls_dir(_1_1_1.0).unwrap().len(), 3);
		assert_eq!(fs_copy.add_or_update_subtree(&[], _1_1_1.0), Ok(()));
		assert_eq!(fs_copy.ls_dir(_1_1_1.0).unwrap().len(), 0);
		//
		let mut fs_copy = fs.clone();
		assert_eq!(fs, fs_copy);

		assert_eq!(fs_copy.ls_dir(_1_1.0).unwrap().len(), 2);
		assert_eq!(fs_copy.add_or_update_subtree(&[], _1_1.0), Ok(()));
		assert_eq!(fs_copy.ls_dir(_1_1.0).unwrap().len(), 0);
		//
		let mut fs_copy = fs.clone();
		assert_eq!(fs, fs_copy);

		assert_eq!(fs_copy.ls_dir(_1.0).unwrap().len(), 2);
		assert_eq!(fs_copy.add_or_update_subtree(&[], _1.0), Ok(()));
		assert_eq!(fs_copy.ls_dir(_1.0).unwrap().len(), 0);
		//
		let mut fs_copy = fs.clone();
		assert_eq!(fs, fs_copy);

		assert_eq!(fs_copy.ls_dir(Uid::new(ROOT_ID)).unwrap().len(), 1);
		assert_eq!(
			fs_copy.add_or_update_subtree(&[], Uid::new(ROOT_ID)),
			Ok(())
		);
		assert_eq!(fs_copy.ls_dir(Uid::new(ROOT_ID)).unwrap().len(), 0);
	}

	#[test]
	fn test_update_node_with_new_and_existing_children() {
		let seed = Seed::generate();
		let god = Identity::generate(Uid::new(0));
		let (mut fs, _) = FileSystem::new(&seed, &god);

		let _1 = fs.mkdir_mut(Uid::new(ROOT_ID), "1", &god).unwrap();
		let _1_1 = fs.mkdir_mut(_1.0, "1_1", &god).unwrap();
		let _1_1_atxt = fs.touch_mut(_1_1.0, 0, "a1", "txt", &god).unwrap();
		let _1_2 = fs.mkdir_mut(_1.0, "1_2", &god).unwrap();
		let _1_1_1 = fs.mkdir_mut(_1_1.0, "1_1_1", &god).unwrap();
		let _1_1_1_atxt = fs.touch_mut(_1_1_1.0, 0, "a", "txt", &god).unwrap();
		let _1_1_1_btxt = fs.touch_mut(_1_1_1.0, 0, "b", "txt", &god).unwrap();
		let _1_1_1_1 = fs.mkdir_mut(_1_1_1.0, "1_1_1_1", &god).unwrap();

		let mut fs_copy = fs.clone();
		assert_eq!(fs, fs_copy);

		// add a few new nodes to a leaf dir
		let _1_1_1_1_1 = fs.mkdir_mut(_1_1_1_1.0, "_1_1_1_1_1", &god).unwrap();
		let _1_1_1_1_2 = fs.mkdir_mut(_1_1_1_1.0, "_1_1_1_1_2", &god).unwrap();
		let _1_1_1_1_atxt = fs
			.touch_mut(_1_1_1_1.0, 0, "_1_1_1_1_a", "txt", &god)
			.unwrap();

		assert_eq!(fs.ls_dir(_1_1_1_1.0).unwrap().len(), 3);

		assert_eq!(
			fs_copy.add_or_update_subtree(
				&vec![_1_1_1_1_1.1, _1_1_1_1_2.1, _1_1_1_1_atxt.1,],
				_1_1_1_1.0
			),
			Ok(())
		);

		assert_eq!(fs, fs_copy);

		// pretend some dirs are removed and some are updated
		assert_eq!(
			fs_copy.add_or_update_subtree(&vec![_1_1.1, _1_1_atxt.1, _1_2.1,], _1.0),
			Ok(())
		);

		assert_eq!(fs_copy.ls_dir(_1.0).unwrap().len(), 2);
		assert_eq!(fs_copy.node_by_id(_1_1_1_1_1.0), None);
		assert_eq!(fs_copy.node_by_id(_1_1_1_1_2.0), None);
		assert_eq!(fs_copy.node_by_id(_1_1_1_1_atxt.0), None);
		assert_eq!(fs_copy.node_by_id(_1_1_1.0), None);
		assert_eq!(fs_copy.node_by_id(_1_1_1_atxt.0), None);
		assert_eq!(fs_copy.node_by_id(_1_1_1_btxt.0), None);
		assert_eq!(fs_copy.node_by_id(_1_1_1_1.0), None);
	}

	#[test]
	fn test_share_parents_and_children() {
		let seed = Seed::generate();
		let god = Identity::generate(Uid::new(0));
		let (mut fs, root) = FileSystem::new(&seed, &god);

		let _1 = fs.mkdir_mut(Uid::new(ROOT_ID), "1", &god).unwrap();
		let _1_1 = fs.mkdir_mut(_1.0, "1_1", &god).unwrap();
		let _1_1_atxt = fs.touch_mut(_1_1.0, 0, "a1", "txt", &god).unwrap();
		let _1_2 = fs.mkdir_mut(_1.0, "1_2", &god).unwrap();
		let _1_1_1 = fs.mkdir_mut(_1_1.0, "1_1_1", &god).unwrap();
		let _1_1_1_atxt = fs.touch_mut(_1_1_1.0, 0, "a", "txt", &god).unwrap();
		let _1_1_1_btxt = fs.touch_mut(_1_1_1.0, 0, "b", "txt", &god).unwrap();
		let _1_1_1_1 = fs.mkdir_mut(_1_1_1.0, "1_1_1_1", &god).unwrap();

		let _1_1_1_a_share = fs.share_node(_1_1_1_atxt.0).unwrap();
		let _1_1_1_b_share = fs.share_node(_1_1_1_btxt.0).unwrap();
		let _1_2_share = fs.share_node(_1_2.0).unwrap();
		let _1_share = fs.share_node(_1.0).unwrap();

		let locked_nodes = vec![
			root,
			_1.1,
			_1_2.1,
			_1_1.1,
			_1_1_1_1.1,
			_1_1_1_atxt.1,
			_1_1_1.1,
			_1_1_1_btxt.1,
			_1_1_atxt.1,
		];
		let bundles = vec![
			(_1_1_1_atxt.0, _1_1_1_a_share),
			(_1_1_1_btxt.0, _1_1_1_b_share),
			(_1_2.0, _1_2_share),
			(_1.0, _1_share),
		]
		.into_iter()
		.collect();

		let fs_partial = FileSystem::from_locked_nodes(&locked_nodes, &bundles);

		assert!(is_dir(&fs_partial, _1.0, "1", Uid::new(ROOT_ID)));
		assert!(is_dir(&fs_partial, _1_2.0, "1_2", _1.0));
		assert!(is_file(&fs_partial, _1_1_1_atxt.0, "a", _1_1_1.0));
		assert!(is_file(&fs_partial, _1_1_1_btxt.0, "b", _1_1_1.0));
		assert_eq!(
			fs_partial.ls_root(),
			vec![fs_partial.node_by_id(_1.0).unwrap()]
		);
	}

	#[test]
	fn test_share_distant_relatives() {
		let seed = Seed::generate();
		let god = Identity::generate(Uid::new(0));
		let (mut fs, root) = FileSystem::new(&seed, &god);

		let _1 = fs.mkdir_mut(Uid::new(ROOT_ID), "1", &god).unwrap();
		let _1_1 = fs.mkdir_mut(_1.0, "1_1", &god).unwrap();
		let _1_1_atxt = fs.touch_mut(_1_1.0, 0, "a1", "txt", &god).unwrap();
		let _1_2 = fs.mkdir_mut(_1.0, "1_2", &god).unwrap();
		let _1_1_1 = fs.mkdir_mut(_1_1.0, "1_1_1", &god).unwrap();
		let _1_1_1_atxt = fs.touch_mut(_1_1_1.0, 0, "a", "txt", &god).unwrap();
		let _1_1_1_btxt = fs.touch_mut(_1_1_1.0, 0, "b", "txt", &god).unwrap();
		let _1_1_1_1 = fs.mkdir_mut(_1_1_1.0, "1_1_1_1", &god).unwrap();

		let _1_1_1_a_share = fs.share_node(_1_1_1_atxt.0).unwrap();
		let _1_1_1_b_share = fs.share_node(_1_1_1_btxt.0).unwrap();
		let root_share = fs.share_node(Uid::new(ROOT_ID)).unwrap();

		let locked_nodes = vec![
			root,
			_1.1,
			_1_2.1,
			_1_1.1,
			_1_1_1_1.1,
			_1_1_1_atxt.1,
			_1_1_1.1,
			_1_1_1_btxt.1,
			_1_1_atxt.1,
		];
		let bundles = vec![
			(_1_1_1_atxt.0, _1_1_1_a_share),
			(_1_1_1_btxt.0, _1_1_1_b_share),
			(Uid::new(ROOT_ID), root_share),
		]
		.into_iter()
		.collect();

		let fs_partial = FileSystem::from_locked_nodes(&locked_nodes, &bundles);

		assert!(is_dir(
			&fs_partial,
			Uid::new(ROOT_ID),
			"/",
			Uid::new(NO_PARENT_ID)
		));
		assert!(is_file(&fs_partial, _1_1_1_atxt.0, "a", _1_1_1.0));
		assert!(is_file(&fs_partial, _1_1_1_btxt.0, "b", _1_1_1.0));
		assert!(fs_partial
			.ls_root()
			.iter()
			.map(|n| n.id)
			.all(|id| [_1.0].contains(&id)));
	}

	#[test]
	fn test_share_root_and_children() {
		let seed = Seed::generate();
		let god = Identity::generate(Uid::new(0));
		let (mut fs, root) = FileSystem::new(&seed, &god);

		let _1 = fs.mkdir_mut(Uid::new(ROOT_ID), "1", &god).unwrap();
		let _2 = fs.mkdir_mut(Uid::new(ROOT_ID), "2", &god).unwrap();
		let _1_1 = fs.mkdir_mut(_1.0, "1_1", &god).unwrap();
		let _1_1_atxt = fs.touch_mut(_1_1.0, 0, "a1", "txt", &god).unwrap();
		let _1_2 = fs.mkdir_mut(_1.0, "1_2", &god).unwrap();
		let _1_1_1 = fs.mkdir_mut(_1_1.0, "1_1_1", &god).unwrap();
		let _1_1_1_atxt = fs.touch_mut(_1_1_1.0, 0, "a", "txt", &god).unwrap();
		let _1_1_1_btxt = fs.touch_mut(_1_1_1.0, 0, "b", "txt", &god).unwrap();
		let _1_1_1_1 = fs.mkdir_mut(_1_1_1.0, "1_1_1_1", &god).unwrap();

		let _1_1_1_a_share = fs.share_node(_1_1_1_atxt.0).unwrap();
		let _1_1_1_b_share = fs.share_node(_1_1_1_btxt.0).unwrap();
		let _1_2_share = fs.share_node(_1_2.0).unwrap();
		let _1_share = fs.share_node(_1.0).unwrap();
		let root_share = fs.share_node(Uid::new(ROOT_ID)).unwrap();

		let locked_nodes = vec![
			root,
			_1.1,
			_2.1,
			_1_2.1,
			_1_1.1,
			_1_1_1_1.1,
			_1_1_1_atxt.1,
			_1_1_1.1,
			_1_1_1_btxt.1,
			_1_1_atxt.1,
		];
		let bundles = vec![
			(_1_1_1_atxt.0, _1_1_1_a_share),
			(_1_1_1_btxt.0, _1_1_1_b_share),
			(Uid::new(ROOT_ID), root_share),
			(_1_2.0, _1_2_share),
			(_1.0, _1_share),
		]
		.into_iter()
		.collect();

		let fs_partial = FileSystem::from_locked_nodes(&locked_nodes, &bundles);

		assert!(is_dir(
			&fs_partial,
			Uid::new(ROOT_ID),
			"/",
			Uid::new(NO_PARENT_ID)
		));
		assert!(is_dir(&fs_partial, _1.0, "1", Uid::new(ROOT_ID)));
		assert!(is_dir(&fs_partial, _2.0, "2", Uid::new(ROOT_ID)));
		assert!(is_dir(&fs_partial, _1_2.0, "1_2", _1.0));
		assert!(is_file(&fs_partial, _1_1_1_atxt.0, "a", _1_1_1.0));
		assert!(is_file(&fs_partial, _1_1_1_btxt.0, "b", _1_1_1.0));

		// root has _1 and _2 in it
		assert!(fs_partial
			.ls_root()
			.iter()
			.map(|n| n.id)
			.all(|id| [_1.0, _2.0].contains(&id)));
	}

	#[test]
	fn test_ls_root_empty() {
		let fs = FileSystem {
			roots: vec![],
			cached_seeds: HashMap::new(),
		};
		let root_entries = fs.ls_root();

		assert!(root_entries.is_empty());
	}
}
