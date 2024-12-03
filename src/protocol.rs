use async_recursion::async_recursion;
use async_trait::async_trait;

use crate::{
	id::Uid,
	identity::{self},
	register::LockedUser,
	seeds::ROOT_ID,
	user::{self, User},
	vault::{self, LockedNode, Node, NO_PARENT_ID},
};

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
	NotFound,
	NoNetwork(String),
	NoAccess,
	BadOperation,
	BadJson,
	ForgedSig,
}

impl From<vault::Error> for Error {
	fn from(er: vault::Error) -> Self {
		match er {
			vault::Error::NotFound => Self::NotFound,
			vault::Error::BadOperation => Self::BadOperation,
			vault::Error::NoAccess => Self::NoAccess,
			vault::Error::ForgedSig => Self::ForgedSig,
		}
	}
}

// to be ffi-exposed; represents cur dir's (or any dir's, in fact) contents and meta
pub struct DirView {
	items: Vec<NodeView>,
	name: String,
	breadcrumbs: Vec<NodeView>,
}

impl DirView {
	pub fn items(&self) -> Vec<NodeView> {
		self.items.clone()
	}

	pub fn breadcrumbs(&self) -> Vec<NodeView> {
		self.breadcrumbs.clone()
	}

	pub fn name(&self) -> String {
		self.name.clone()
	}
}

// to be ffi-exposed; a generic view to a node and its meta
#[derive(Clone)]
pub struct NodeView {
	id: Uid,
	created_at: u64,
	size: u32,
	name: String,
	ext: Option<String>,
}

impl NodeView {
	pub fn is_dir(&self) -> bool {
		self.ext.is_none()
	}

	pub fn id(&self) -> Uid {
		self.id
	}

	pub fn size(&self) -> u32 {
		self.size
	}

	pub fn name(&self) -> String {
		self.name.clone()
	}

	pub fn created_at(&self) -> u64 {
		self.created_at
	}

	// nil for a dir apparently; could be nil for a file, if unspecified
	pub fn ext(&self) -> Option<String> {
		self.ext.clone()
	}
}

#[async_trait(?Send)]
pub trait Network {
	async fn fetch_subtree(&self, id: Uid) -> Result<Vec<LockedNode>, Error>;
}

// to be ffi-exposed; contains all the state required to use Vault
pub struct Protocol {
	// current directory
	cd: Option<Uid>,
	user: User,
	// callbacks
	net: Box<dyn Network>,
}

impl From<Node> for NodeView {
	fn from(node: Node) -> Self {
		let (ext, size) = match node.entry {
			vault::Entry::File { info } => (Some(info.ext), info.size),
			vault::Entry::Dir {
				seed: _,
				children: _,
			} => (None, 0),
		};

		Self {
			id: node.id,
			size,
			created_at: node.created_at,
			name: node.name,
			ext,
		}
	}
}

impl TryFrom<Node> for DirView {
	type Error = Error;

	fn try_from(dir: Node) -> Result<Self, Self::Error> {
		if let vault::Entry::Dir {
			seed: _,
			children: ref nodes,
		} = dir.entry
		{
			let items = nodes.iter().map(|n| n.clone().into()).collect();

			Ok(DirView {
				items,
				name: dir.name,
				breadcrumbs: Vec::new(),
			})
		} else {
			Err(Error::BadOperation)
		}
	}
}

struct NoNetwork;

#[async_trait(?Send)]
impl Network for NoNetwork {
	async fn fetch_subtree(&self, _id: Uid) -> Result<Vec<LockedNode>, Error> {
		todo!("fetch_subtree is not implemented for Protocol<NoNetwork>");
	}
}

impl Protocol {
	pub fn new_no_network(
		ident_priv: identity::Private,
		locked: LockedUser,
	) -> Result<Self, Error> {
		Self::new(ident_priv, locked, Box::new(NoNetwork))
	}

	fn new(
		ident_priv: identity::Private,
		locked: LockedUser,
		net: Box<dyn Network>,
	) -> Result<Self, Error> {
		Ok(Self {
			cd: None,
			user: user::unlock_with_params(
				&ident_priv,
				&locked._pub,
				&locked.shares,
				&locked.roots,
			)
			.map_err(|_| Error::NoAccess)?,
			net: net,
		})
	}

	// lists cur dir's content
	pub async fn ls_cur_mut(&mut self) -> Result<DirView, Error> {
		self.ls_cur_mut_impl().await
	}

	// ls current dir and refetch, if needed
	#[async_recursion(?Send)]
	async fn ls_cur_mut_impl(&mut self) -> Result<DirView, Error> {
		if let Some(cd) = self.cd {
			if let Some(node) = self.user.fs.node_by_id(cd) {
				// TODO: check whether this dir has a child that's dirty?
				if node.dirty {
					let nodes = self.net.fetch_subtree(cd).await?;
					_ = self
						.user
						.fs
						// TODO: wrap in a channel instead
						.add_or_update_subtree(&nodes, cd)
						.map_err(|_| Error::NotFound)?;

					// TODO: refactor to avoid recursion
					self.ls_cur_mut_impl().await
				} else {
					let mut breadcrumbs = Vec::new();
					let mut cur = node.parent_id;

					while cur != NO_PARENT_ID {
						let cur_node = self.user.fs.node_by_id(cur);

						breadcrumbs.push(NodeView {
							id: cur,
							created_at: cur_node.map_or(0, |n| n.created_at),
							size: 0,
							name: cur_node.map_or("~".to_string(), |n| n.name.clone()),
							ext: None,
						});

						cur = cur_node.map_or(Uid::new(NO_PARENT_ID), |n| n.parent_id);
					}

					breadcrumbs.reverse();

					Ok(DirView {
						breadcrumbs,
						..node.clone().try_into()?
					})
				}
			} else {
				Ok(self.cd_to_root().await)
			}
		} else {
			// TODO: how about dirty?
			Ok(self.cd_to_root().await)
		}
	}

	async fn cd_to_root(&mut self) -> DirView {
		// TODO: this should not be await and hard unwrapping
		if let Some(_) = self.user.fs.node_by_id(Uid::new(ROOT_ID)) {
			self.cd_to_dir(&Uid::new(ROOT_ID)).await.unwrap()
		} else {
			self.cd = None;

			let items = self
				.user
				.fs
				.ls_root()
				.iter()
				.map(|&n| n.clone().into())
				.collect();

			DirView {
				items,
				name: "~".to_string(),
				breadcrumbs: Vec::new(),
			}
		}
	}

	// goes one level higher in the hierarchy
	pub async fn go_back(&mut self) -> Result<DirView, Error> {
		if let Some(cd) = self.cd {
			if let Some(node) = self.user.fs.node_by_id(cd) {
				let parent_id = node.parent_id;
				self.cd_to_dir(&parent_id).await
			} else {
				Ok(self.cd_to_root().await)
			}
		} else {
			Ok(self.cd_to_root().await)
		}
	}

	// jumps to any dir; useful to handle breadcrumbs nav
	pub async fn cd_to_dir(&mut self, id: &Uid) -> Result<DirView, Error> {
		self.cd = Some(*id);

		self.ls_cur_mut_impl().await
	}

	pub async fn chunk_decrypt_for_file(
		&self,
		chunk: &[u8],
		file_id: &Uid,
		chunk_idx: u32,
	) -> Result<Vec<u8>, Error> {
		if let Some(node) = self.user.fs.node_by_id(*file_id) {
			if let vault::Entry::File { ref info } = node.entry {
				let pt = info
					.key_iv
					.chunk_decrypt_async(chunk_idx, chunk)
					.await
					.map_err(|_| Error::NoAccess)?;

				Ok(Vec::from(pt.as_slice()))
			} else {
				Err(Error::BadOperation)
			}
		} else {
			Err(Error::NotFound)
		}
	}
}
