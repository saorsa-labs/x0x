//! Real RFC-9420 TreeKEM group encryption, wrapping `saorsa_mls::TreeKemGroup`.
//!
//! Unlike the legacy GSS plane in `crate::mls::group` (a per-epoch shared
//! secret with no forward secrecy / no post-compromise security), this plane
//! provides genuine **forward secrecy** and **post-compromise security** via a
//! KEM-keypair-per-node ratchet tree, UpdatePath/Commit distribution, and
//! init→commit→epoch key-schedule chaining. New `MlsEncrypted` groups use this
//! plane (ADR-0012).
//!
//! ## Boundary
//!
//! The daemon talks to this wrapper in **bytes**, not `saorsa_mls` types:
//! `Commit`s, `Welcome`s, key packages, and ciphertexts all cross the wrapper
//! boundary as postcard-encoded `Vec<u8>` so the rest of x0x never depends on
//! the upstream wire types directly.
//!
//! ## Identity
//!
//! Each member's `saorsa_mls::MemberIdentity` is **derived deterministically**
//! from a per-group 32-byte seed via `MemberIdentity::from_seed` (saorsa-mls
//! 0.3.7+). The daemon builds that seed with [`derive_identity_seed`], binding
//! the agent's long-term secret key material to the `group_id` — so the TreeKEM
//! leaf is tied to the agent's real identity, the same identity is **re-derivable
//! after a restart** (enabling [`TreeKemMlsGroup::restore`]), and an agent's
//! per-group **keys** (`verifying_key` / `agreement_key`) are distinct and
//! unlinkable across groups.
//!
//! Unlinkability: both the per-group **keys** (`verifying_key` /
//! `agreement_key`) and the saorsa-mls `MemberId` are derived from the per-group
//! seed (see `member_id_from_seed`), so the `MemberId` label embedded in each
//! `KeyPackage` credential is **distinct and unlinkable across the groups an
//! agent joins** — a member who shares two groups with the agent cannot
//! correlate them by `MemberId`. This is the per-group decision recorded in
//! ADR-0012 (review finding #2). The legacy GSS plane (`crate::mls::group`)
//! keeps the stable per-agent `crate::mls::agent_id_to_member_id` label; the
//! two planes deliberately use different `MemberId`s.
//!
//! Determinism contract: the same `(agent, seed)` yields the same *public keys*
//! (so a restored identity re-attaches to its leaf), but **not** a byte-identical
//! `KeyPackage` — ML-DSA signing is randomized upstream. saorsa-mls matches
//! leaves on stable public keys, so this is sufficient for restart + cross-daemon
//! join.

use crate::identity::AgentId;
use crate::mls::{MlsError, Result};
use saorsa_mls::{
    treekem_group::{ApplicationCiphertext, TreeKemCommit, TreeKemGroup, TreeKemWelcome},
    CipherSuite, KeyPackage, MemberIdentity,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Derive the 32-byte TreeKEM identity seed for an agent in a specific group.
///
/// `agent_secret` is the agent's long-term secret key material (e.g.
/// `AgentKeypair::secret_key().to_bytes()`). Binding `group_id` gives the agent a
/// **distinct, unlinkable** TreeKEM identity per group, while staying fully
/// deterministic so the same identity is re-derivable across daemon restarts
/// (the basis for persistence) and the leaf is bound to the agent's real
/// identity (ADR-0012 Phase 2). Inputs are length-prefixed to avoid
/// concatenation ambiguity; the BLAKE3 derive-key mode domain-separates this use.
#[must_use]
pub fn derive_identity_seed(agent_secret: &[u8], group_id: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("x0x treekem identity seed v1");
    hasher.update(&(agent_secret.len() as u64).to_le_bytes());
    hasher.update(agent_secret);
    hasher.update(&(group_id.len() as u64).to_le_bytes());
    hasher.update(group_id);
    *hasher.finalize().as_bytes()
}

/// Derive the per-group saorsa-mls `MemberId` (16 bytes) from the identity
/// `seed`.
///
/// Unlike the legacy GSS plane's `crate::mls::agent_id_to_member_id` (the
/// stable first-16-bytes-of-`AgentId` label, identical across an agent's
/// groups), this binds the `MemberId` to the per-group seed — which already
/// folds in the agent's secret and the `group_id` (see [`derive_identity_seed`]).
/// The result is a `MemberId` that is **unlinkable across groups** yet
/// deterministic, so a restored identity re-derives the same label and
/// re-attaches to its leaf. Resolves ADR-0012 review finding #2. The BLAKE3
/// derive-key mode domain-separates this from other uses of the seed.
fn member_id_from_seed(seed: &[u8; 32]) -> saorsa_mls::MemberId {
    let mut hasher = blake3::Hasher::new_derive_key("x0x treekem member-id v1");
    hasher.update(seed);
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    saorsa_mls::MemberId::from_bytes(bytes)
}

fn encode<T: Serialize>(value: &T, what: &str) -> Result<Vec<u8>> {
    postcard::to_stdvec(value).map_err(|e| MlsError::MlsOperation(format!("encode {what}: {e}")))
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8], what: &str) -> Result<T> {
    postcard::from_bytes(bytes).map_err(|e| MlsError::MlsOperation(format!("decode {what}: {e}")))
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedTreeKemSnapshot {
    version: u8,
    inner_snapshot: Vec<u8>,
    agent_to_leaf: Vec<([u8; 32], u32)>,
}

const PERSISTED_SNAPSHOT_VERSION: u8 = 1;
const PERSISTED_SNAPSHOT_MAGIC: &[u8; 4] = b"XTK1";

/// A member's freshly-minted identity plus the public key package to hand to an
/// inviter. The holder keeps the (private) identity until a `Welcome` arrives,
/// then consumes it via [`TreeKemMlsGroup::join_from_welcome`].
///
/// Carries the agent's KEM/signing **secret** key material in memory; never
/// serialize this to disk in the clear.
pub struct PreparedMember {
    agent: AgentId,
    identity: MemberIdentity,
    key_package_bytes: Vec<u8>,
}

impl PreparedMember {
    /// The serialized public `KeyPackage` to publish / hand to the inviter so
    /// they can call [`TreeKemMlsGroup::add_member`].
    #[must_use]
    pub fn key_package_bytes(&self) -> &[u8] {
        &self.key_package_bytes
    }

    /// The agent this prepared identity belongs to.
    #[must_use]
    pub fn agent(&self) -> &AgentId {
        &self.agent
    }
}

impl std::fmt::Debug for PreparedMember {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedMember")
            .field("agent", &self.agent)
            .field(
                "key_package_bytes",
                &format!("{} bytes", self.key_package_bytes.len()),
            )
            .finish_non_exhaustive()
    }
}

/// Output of [`TreeKemMlsGroup::add_member`]: a `Commit` for existing members
/// and a `Welcome` for the joiner, both postcard-encoded.
#[derive(Debug, Clone)]
pub struct AddMemberOutput {
    /// Encoded [`TreeKemCommit`] — deliver to every existing member; they call
    /// [`TreeKemMlsGroup::process_commit`].
    pub commit: Vec<u8>,
    /// Encoded [`TreeKemWelcome`] — deliver to the joiner; they call
    /// [`TreeKemMlsGroup::join_from_welcome`].
    pub welcome: Vec<u8>,
}

/// A real TreeKEM group as held by one member, keyed by x0x [`AgentId`].
///
/// The live group does not retain the member identity; it is re-derived from the
/// per-group seed on restore — see [`Self::restore`].
pub struct TreeKemMlsGroup {
    inner: TreeKemGroup,
    /// Best-effort `AgentId → leaf` map, populated from operations this instance
    /// performs (own leaf, members it adds). The named-group roster
    /// (`src/groups`) is the authoritative roster; this exists so the wrapper
    /// can resolve an agent to a leaf for [`Self::remove_member`].
    agent_to_leaf: HashMap<AgentId, u32>,
}

impl std::fmt::Debug for TreeKemMlsGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TreeKemMlsGroup")
            .field("inner", &self.inner)
            .field("members_tracked", &self.agent_to_leaf.len())
            .finish_non_exhaustive()
    }
}

impl TreeKemMlsGroup {
    /// Cipher suite used for all x0x TreeKEM groups: ML-KEM-768 + ML-DSA-65 +
    /// ChaCha20-Poly1305 (saorsa-mls SPEC-2 default, `0x0B01`).
    fn suite() -> CipherSuite {
        CipherSuite::default()
    }

    /// Deterministically derive a `MemberIdentity` from a per-group `seed`. The
    /// same `seed` always yields an identity with the same `MemberId` and the
    /// same public keys, so it re-attaches to its leaf after a restart
    /// (saorsa-mls matches leaves on stable public keys, not byte-identical key
    /// packages — ML-DSA signing is randomized upstream). Both the `MemberId`
    /// (`member_id_from_seed`) and the keys are bound to the seed, giving
    /// per-group unlinkability (ADR-0012 finding #2).
    fn identity_from_seed(seed: &[u8; 32]) -> Result<MemberIdentity> {
        let member_id = member_id_from_seed(seed);
        MemberIdentity::from_seed(member_id, Self::suite(), seed)
            .map_err(|e| MlsError::Identity(format!("from_seed: {e}")))
    }

    /// Create a fresh single-member group owned by `creator` (leaf 0).
    ///
    /// `seed` is the creator's per-group identity seed (see
    /// [`derive_identity_seed`]). The same seed restores this member's identity
    /// in [`Self::restore`] after a restart.
    ///
    /// # Errors
    /// Returns [`MlsError`] if identity derivation or group creation fails.
    pub fn create(group_id: Vec<u8>, creator: AgentId, seed: &[u8; 32]) -> Result<Self> {
        let identity = Self::identity_from_seed(seed)?;
        let inner = TreeKemGroup::create(group_id, identity)
            .map_err(|e| MlsError::SaorsaMls(format!("treekem create: {e}")))?;

        let mut agent_to_leaf = HashMap::new();
        if let Some(leaf) = inner.own_leaf() {
            agent_to_leaf.insert(creator, leaf);
        }
        Ok(Self {
            inner,
            agent_to_leaf,
        })
    }

    /// Derive `agent`'s member identity + public key package (from `seed`) to be
    /// handed to a group member who will call [`Self::add_member`]. The returned
    /// [`PreparedMember`] must be retained until the `Welcome` arrives.
    ///
    /// Because the identity is deterministic in `seed`, the joiner can re-derive
    /// the same identity later for [`Self::restore`] without persisting it.
    ///
    /// # Errors
    /// Returns [`MlsError`] if identity derivation or key-package encoding fails.
    pub fn prepare_member(agent: AgentId, seed: &[u8; 32]) -> Result<PreparedMember> {
        let identity = Self::identity_from_seed(seed)?;
        let key_package_bytes = encode(&identity.key_package, "key package")?;
        Ok(PreparedMember {
            agent,
            identity,
            key_package_bytes,
        })
    }

    /// Add `joiner` (identified by their published key-package bytes) to the
    /// group. Returns the `Commit` for existing members and the `Welcome` for
    /// the joiner. This instance advances to the next epoch.
    ///
    /// # Errors
    /// Returns [`MlsError`] if the key package is invalid, the suite mismatches,
    /// or the TreeKEM operation fails.
    pub fn add_member(
        &mut self,
        joiner: AgentId,
        joiner_key_package: &[u8],
    ) -> Result<AddMemberOutput> {
        // Reject re-adding an agent this instance already tracks. saorsa-mls
        // does NOT dedup — `tree.add_leaf` would assign a *second* leaf to the
        // same agent, and the `agent_to_leaf` insert below would overwrite the
        // first, orphaning it (a later remove would leave the first leaf live
        // and able to decrypt). The authoritative dedup is the named-group
        // roster in `src/groups`; this guard catches the common case locally.
        if self.agent_to_leaf.contains_key(&joiner) {
            return Err(MlsError::MlsOperation(format!(
                "agent {:?} is already a member of this group",
                joiner.as_bytes()
            )));
        }
        let kp: KeyPackage = decode(joiner_key_package, "joiner key package")?;
        let (commit, welcome) = self
            .inner
            .add_member(&kp)
            .map_err(|e| MlsError::SaorsaMls(format!("treekem add_member: {e}")))?;

        // Record the joiner's leaf from the commit so we can resolve it later.
        if let Some((leaf, _)) = commit.added.first() {
            self.agent_to_leaf.insert(joiner, *leaf);
        }

        Ok(AddMemberOutput {
            commit: encode(&commit, "commit")?,
            welcome: encode(&welcome, "welcome")?,
        })
    }

    /// Join an existing group from a `Welcome`, consuming the prepared identity
    /// whose key package produced it.
    ///
    /// # Errors
    /// Returns [`MlsError`] if the welcome is malformed or fails verification.
    pub fn join_from_welcome(prepared: PreparedMember, welcome: &[u8]) -> Result<Self> {
        let welcome: TreeKemWelcome = decode(welcome, "welcome")?;
        let joiner = prepared.agent;
        let inner = TreeKemGroup::from_welcome(&welcome, prepared.identity)
            .map_err(|e| MlsError::Welcome(format!("treekem from_welcome: {e}")))?;

        let mut agent_to_leaf = HashMap::new();
        if let Some(leaf) = inner.own_leaf() {
            agent_to_leaf.insert(joiner, leaf);
        }
        Ok(Self {
            inner,
            agent_to_leaf,
        })
    }

    /// Apply a `Commit` produced by another member (add / remove / rekey).
    ///
    /// # Errors
    /// Returns [`MlsError`] if the commit is malformed or fails verification.
    pub fn process_commit(&mut self, commit: &[u8]) -> Result<()> {
        let commit: TreeKemCommit = decode(commit, "commit")?;
        let mut next_agent_to_leaf = self.agent_to_leaf.clone();
        if !commit.removed_leaves.is_empty() {
            let removed: std::collections::HashSet<u32> =
                commit.removed_leaves.iter().copied().collect();
            next_agent_to_leaf.retain(|_, leaf| !removed.contains(leaf));
        }
        self.inner
            .process_commit(&commit)
            .map_err(|e| MlsError::SaorsaMls(format!("treekem process_commit: {e}")))?;
        self.agent_to_leaf = next_agent_to_leaf;
        Ok(())
    }

    /// Produce a `Commit` removing `member` from the group. The caller delivers
    /// it to all remaining members.
    ///
    /// **Resolution caveat (Phase 1/2):** this instance can only resolve agents
    /// it added itself, plus its own leaf — `process_commit` cannot learn the
    /// `AgentId` of members *another* daemon added (the wire `Commit` carries
    /// only `(leaf, KeyPackage)`, no `AgentId`, and the AgentId↔identity binding
    /// is not wired until ADR-0012 Phase 2/4). Drive removal from the
    /// authoritative named-group roster (`src/groups`), which knows every
    /// member's `AgentId`, rather than relying on this instance's best-effort
    /// map.
    ///
    /// # Errors
    /// Returns [`MlsError::MemberNotInGroup`] if the agent's leaf is unknown to
    /// this instance, or [`MlsError`] on TreeKEM failure.
    pub fn remove_member(&mut self, member: AgentId) -> Result<Vec<u8>> {
        let leaf = self.agent_to_leaf.get(&member).copied().ok_or_else(|| {
            MlsError::MemberNotInGroup(format!("unknown leaf for {:?}", member.as_bytes()))
        })?;
        self.remove_leaf_for_member(member, leaf)
    }

    /// Produce a `Commit` removing `member`, but only after verifying that the
    /// resolved leaf's public TreeKEM keys still match the authoritative roster
    /// key package for that agent.
    ///
    /// This closes the stale-map wrong-leaf hazard: the best-effort
    /// `agent_to_leaf` map can identify a candidate leaf, but the public keys in
    /// the ratchet tree must match the roster's KeyPackage before removal is
    /// allowed.
    pub fn remove_member_verified(
        &mut self,
        member: AgentId,
        expected_key_package: &[u8],
    ) -> Result<Vec<u8>> {
        let kp: KeyPackage = decode(expected_key_package, "expected member key package")?;
        let leaf = self.inner.find_leaf_by_key_package(&kp).ok_or_else(|| {
            MlsError::MemberNotInGroup(format!(
                "no active TreeKEM leaf matching roster KeyPackage for {:?}",
                member.as_bytes()
            ))
        })?;
        self.remove_leaf_for_member(member, leaf)
    }

    fn remove_leaf_for_member(&mut self, member: AgentId, leaf: u32) -> Result<Vec<u8>> {
        let commit = self
            .inner
            .remove_member(leaf)
            .map_err(|e| MlsError::SaorsaMls(format!("treekem remove_member: {e}")))?;
        self.agent_to_leaf.remove(&member);
        encode(&commit, "commit")
    }

    /// Produce an update `Commit` that rotates this member's key material
    /// (post-compromise healing). Deliver to all members.
    ///
    /// # Errors
    /// Returns [`MlsError`] on TreeKEM failure.
    pub fn update(&mut self) -> Result<Vec<u8>> {
        let commit = self
            .inner
            .update()
            .map_err(|e| MlsError::SaorsaMls(format!("treekem update: {e}")))?;
        encode(&commit, "commit")
    }

    /// Encrypt an application message for the group. Returns encoded
    /// [`ApplicationCiphertext`].
    ///
    /// # Errors
    /// Returns [`MlsError::EncryptionError`] on failure.
    pub fn encrypt_message(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let ct = self
            .inner
            .encrypt_message(plaintext)
            .map_err(|e| MlsError::EncryptionError(e.to_string()))?;
        encode(&ct, "ciphertext")
    }

    /// Decrypt an application message produced by a group member.
    ///
    /// # Errors
    /// Returns [`MlsError::DecryptionError`] on malformed input or failure.
    pub fn decrypt_message(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let ct: ApplicationCiphertext = decode(ciphertext, "ciphertext")
            .map_err(|e| MlsError::DecryptionError(e.to_string()))?;
        self.inner
            .decrypt_message(&ct)
            .map_err(|e| MlsError::DecryptionError(e.to_string()))
    }

    /// The group's current epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.inner.epoch()
    }

    /// The group identifier.
    #[must_use]
    pub fn group_id(&self) -> &[u8] {
        self.inner.group_id()
    }

    /// Number of active members.
    #[must_use]
    pub fn member_count(&self) -> u32 {
        self.inner.member_count()
    }

    /// Serialize the full group state for persistence. **Contains private key
    /// material** — the caller MUST protect it at rest (Phase 4 persists it with
    /// the same `0600` model x0x uses for other key files; see ADR-0012).
    ///
    /// # Errors
    /// Returns [`MlsError`] on snapshot/encode failure.
    pub fn to_snapshot_bytes(&self) -> Result<Vec<u8>> {
        let inner_snapshot = self
            .inner
            .to_snapshot_bytes()
            .map_err(|e| MlsError::MlsOperation(format!("treekem snapshot: {e}")))?;
        let agent_to_leaf = self
            .agent_to_leaf
            .iter()
            .map(|(agent, leaf)| (*agent.as_bytes(), *leaf))
            .collect();
        let mut bytes = PERSISTED_SNAPSHOT_MAGIC.to_vec();
        bytes.extend(encode(
            &PersistedTreeKemSnapshot {
                version: PERSISTED_SNAPSHOT_VERSION,
                inner_snapshot,
                agent_to_leaf,
            },
            "persisted treekem snapshot",
        )?);
        Ok(bytes)
    }

    /// Restore a group from a snapshot for `member`, re-deriving the identity
    /// from `seed`.
    ///
    /// This works for **any** member — creator or joiner — because the identity
    /// is deterministic in `seed` alone: pass the same per-group seed used at
    /// [`Self::create`] / [`Self::prepare_member`] time and the re-derived
    /// identity re-attaches to its leaf (saorsa-mls matches on stable public
    /// keys). A snapshot restored with the wrong `seed` is rejected by the inner
    /// owner-leaf check. `member` only labels this instance's local
    /// `agent_to_leaf` map; the daemon always pairs an agent with the seed
    /// derived from *its own* secret, so a caller cannot accidentally restore
    /// another agent's leaf without also holding that agent's seed.
    ///
    /// # Errors
    /// Returns [`MlsError`] if the snapshot is malformed, or the re-derived
    /// identity does not own a leaf in the snapshot (wrong `seed`).
    pub fn restore(snapshot: &[u8], member: AgentId, seed: &[u8; 32]) -> Result<Self> {
        let identity = Self::identity_from_seed(seed)?;
        let (inner_snapshot, persisted_map) = if let Some(wrapped) =
            snapshot.strip_prefix(PERSISTED_SNAPSHOT_MAGIC)
        {
            let persisted: PersistedTreeKemSnapshot =
                decode(wrapped, "persisted treekem snapshot")?;
            if persisted.version != PERSISTED_SNAPSHOT_VERSION {
                return Err(MlsError::MlsOperation(format!(
                    "unsupported treekem snapshot version {}",
                    persisted.version
                )));
            }
            (persisted.inner_snapshot, Some(persisted.agent_to_leaf))
        } else {
            match decode::<PersistedTreeKemSnapshot>(snapshot, "legacy persisted treekem snapshot")
            {
                Ok(persisted) if persisted.version == PERSISTED_SNAPSHOT_VERSION => {
                    (persisted.inner_snapshot, Some(persisted.agent_to_leaf))
                }
                _ => (snapshot.to_vec(), None),
            }
        };
        let inner = TreeKemGroup::from_snapshot_bytes(&inner_snapshot, identity)
            .map_err(|e| MlsError::MlsOperation(format!("treekem restore: {e}")))?;
        let mut agent_to_leaf: HashMap<AgentId, u32> = persisted_map
            .unwrap_or_default()
            .into_iter()
            .map(|(agent, leaf)| (AgentId(agent), leaf))
            .collect();
        if let Some(leaf) = inner.own_leaf() {
            agent_to_leaf.insert(member, leaf);
        }
        Ok(Self {
            inner,
            agent_to_leaf,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(id: u8) -> AgentId {
        // The TreeKEM identity (keys + MemberId) is derived from the per-group
        // seed, not the AgentId, so distinct test seeds are what give distinct
        // identities; the exact AgentId bytes only label the local leaf map.
        let mut bytes = [0u8; 32];
        bytes[0] = id;
        bytes[1] = id.wrapping_mul(7).wrapping_add(1);
        AgentId(bytes)
    }

    /// Deterministic per-agent seed for tests (stands in for the daemon's
    /// `derive_identity_seed(agent_secret, group_id)`).
    fn seed(id: u8) -> [u8; 32] {
        [id; 32]
    }

    #[test]
    fn create_solo_encrypt_decrypt_roundtrip() {
        let mut g = TreeKemMlsGroup::create(b"room".to_vec(), agent(1), &seed(1)).expect("create");
        assert_eq!(g.epoch(), 0);
        assert_eq!(g.member_count(), 1);
        let ct = g.encrypt_message(b"hello self").expect("encrypt");
        let pt = g.decrypt_message(&ct).expect("decrypt");
        assert_eq!(pt, b"hello self");
    }

    #[test]
    fn cross_instance_join_over_the_wire_then_exchange() {
        // Alice creates; Bob prepares an identity and publishes a key package.
        let alice_id = agent(1);
        let bob_id = agent(2);
        let mut alice =
            TreeKemMlsGroup::create(b"group-A".to_vec(), alice_id, &seed(1)).expect("alice create");
        let bob_prepared = TreeKemMlsGroup::prepare_member(bob_id, &seed(2)).expect("bob prepare");

        // Everything crosses the boundary as bytes (simulating the wire).
        let kp_bytes = bob_prepared.key_package_bytes().to_vec();
        let out = alice.add_member(bob_id, &kp_bytes).expect("add_member");

        // Bob joins from the Welcome bytes with the identity he prepared.
        let mut bob =
            TreeKemMlsGroup::join_from_welcome(bob_prepared, &out.welcome).expect("bob join");

        // Both at the same post-add epoch with two members.
        assert_eq!(alice.epoch(), bob.epoch(), "epochs must converge");
        assert_eq!(alice.member_count(), 2);
        assert_eq!(bob.member_count(), 2);

        // Alice → Bob: real cross-instance decryption (FS/PCS path).
        let ct = alice
            .encrypt_message(b"welcome to the group")
            .expect("encrypt");
        let pt = bob.decrypt_message(&ct).expect("bob decrypt");
        assert_eq!(pt, b"welcome to the group");

        // Bob → Alice as well.
        let ct2 = bob.encrypt_message(b"glad to be here").expect("encrypt");
        let pt2 = alice.decrypt_message(&ct2).expect("alice decrypt");
        assert_eq!(pt2, b"glad to be here");
    }

    #[test]
    fn wrong_group_message_does_not_decrypt() {
        let mut a = TreeKemMlsGroup::create(b"group-A".to_vec(), agent(1), &seed(1)).expect("a");
        let mut b = TreeKemMlsGroup::create(b"group-B".to_vec(), agent(2), &seed(2)).expect("b");
        let ct = a.encrypt_message(b"secret A").expect("encrypt");
        assert!(
            b.decrypt_message(&ct).is_err(),
            "a group-A ciphertext must not decrypt in group B"
        );
    }

    #[test]
    fn snapshot_bytes_have_magic_header_and_restore() {
        let alice_id = agent(1);
        let g = TreeKemMlsGroup::create(b"magic".to_vec(), alice_id, &seed(1)).expect("create");
        let snap = g.to_snapshot_bytes().expect("snapshot");
        assert!(snap.starts_with(PERSISTED_SNAPSHOT_MAGIC));
        let restored = TreeKemMlsGroup::restore(&snap, alice_id, &seed(1)).expect("restore");
        assert_eq!(restored.epoch(), g.epoch());
    }

    #[test]
    fn restart_persistence_creator_restores_and_decrypts() {
        // Alice creates a group and adds Bob, then "restarts": her live group is
        // dropped and rebuilt from (snapshot bytes + re-derived identity). The
        // restored instance must decrypt a message Bob sends afterwards — proving
        // the snapshot preserves epoch secrets and the from_seed identity
        // re-attaches to Alice's leaf. This is the persistence the session-scoped
        // wrapper could not do before saorsa-mls 0.3.7's from_seed.
        let alice_id = agent(1);
        let bob_id = agent(2);
        let mut alice =
            TreeKemMlsGroup::create(b"persist".to_vec(), alice_id, &seed(1)).expect("create");
        let bob_prepared = TreeKemMlsGroup::prepare_member(bob_id, &seed(2)).expect("prepare");
        let out = alice
            .add_member(bob_id, bob_prepared.key_package_bytes())
            .expect("add");
        let mut bob = TreeKemMlsGroup::join_from_welcome(bob_prepared, &out.welcome).expect("join");

        // Snapshot Alice, then drop the live instance.
        let snap = alice.to_snapshot_bytes().expect("snapshot");
        drop(alice);

        // Re-derive Alice's identity from the SAME seed and restore.
        let mut alice2 = TreeKemMlsGroup::restore(&snap, alice_id, &seed(1)).expect("restore");
        assert_eq!(alice2.member_count(), 2);

        // Bob → restored Alice round-trips.
        let ct = bob.encrypt_message(b"after restart").expect("encrypt");
        let pt = alice2.decrypt_message(&ct).expect("restored alice decrypt");
        assert_eq!(pt, b"after restart");
    }

    #[test]
    fn owner_restore_preserves_leaf_map_for_remove() {
        let alice_id = agent(1);
        let bob_id = agent(2);
        let mut alice =
            TreeKemMlsGroup::create(b"persist-map".to_vec(), alice_id, &seed(1)).expect("create");
        let bob_prepared = TreeKemMlsGroup::prepare_member(bob_id, &seed(2)).expect("prepare");
        alice
            .add_member(bob_id, bob_prepared.key_package_bytes())
            .expect("add bob");
        let snap = alice.to_snapshot_bytes().expect("snapshot");

        let mut restored = TreeKemMlsGroup::restore(&snap, alice_id, &seed(1)).expect("restore");
        let remove_commit = restored
            .remove_member(bob_id)
            .expect("remove after restore");
        assert!(!remove_commit.is_empty());
        assert_eq!(restored.member_count(), 1);
    }

    #[test]
    fn restore_with_wrong_seed_is_rejected() {
        let alice_id = agent(1);
        let g = TreeKemMlsGroup::create(b"snap".to_vec(), alice_id, &seed(1)).expect("create");
        let snap = g.to_snapshot_bytes().expect("snapshot");
        // Same agent, different seed -> different identity keys -> no matching
        // leaf -> rejected (not a panic).
        let restored = TreeKemMlsGroup::restore(&snap, alice_id, &seed(9));
        assert!(restored.is_err(), "restore with the wrong seed must fail");
    }

    #[test]
    fn from_seed_is_deterministic() {
        // Same (agent, seed) -> same key package public material; the identity is
        // re-derivable, which is what makes restart persistence work.
        let a = TreeKemMlsGroup::prepare_member(agent(5), &seed(5)).expect("p1");
        let b = TreeKemMlsGroup::prepare_member(agent(5), &seed(5)).expect("p2");
        let kp_a: KeyPackage = decode(a.key_package_bytes(), "kp").expect("decode a");
        let kp_b: KeyPackage = decode(b.key_package_bytes(), "kp").expect("decode b");
        assert_eq!(
            kp_a.verifying_key, kp_b.verifying_key,
            "same seed must yield the same signing public key"
        );
        assert_eq!(
            kp_a.agreement_key, kp_b.agreement_key,
            "same seed must yield the same KEM public key"
        );
    }

    #[test]
    fn derive_identity_seed_binds_group() {
        // Same agent secret, different group -> different seed (per-group
        // unlinkable identities).
        let secret = b"agent-secret-key-bytes";
        let s1 = derive_identity_seed(secret, b"group-A");
        let s2 = derive_identity_seed(secret, b"group-B");
        assert_ne!(s1, s2, "different groups must yield different seeds");
        let s1b = derive_identity_seed(secret, b"group-A");
        assert_eq!(s1, s1b, "derivation must be deterministic");
    }

    #[test]
    fn member_id_is_per_group_and_deterministic() {
        // ADR-0012 finding #2: the MemberId must be unlinkable across groups.
        // Two different per-group seeds -> different MemberIds; the same seed
        // always yields the same MemberId (so restore re-derives it).
        let secret = b"agent-secret-key-bytes";
        let seed_a = derive_identity_seed(secret, b"group-A");
        let seed_b = derive_identity_seed(secret, b"group-B");
        assert_ne!(
            member_id_from_seed(&seed_a),
            member_id_from_seed(&seed_b),
            "the same agent in two groups must get distinct MemberIds"
        );
        assert_eq!(
            member_id_from_seed(&seed_a),
            member_id_from_seed(&seed_a),
            "MemberId derivation must be deterministic"
        );
    }

    #[test]
    fn same_agent_in_two_groups_is_cryptographically_unlinkable() {
        // ADR-0012 finding #2 end-to-end: one agent, two groups -> the published
        // KeyPackages share NO public material (keys *and* credential differ), so
        // an observer in both groups cannot correlate the agent.
        let agent_id = agent(1);
        let secret = b"the-agents-long-term-secret";
        let kp_a: KeyPackage = decode(
            TreeKemMlsGroup::prepare_member(agent_id, &derive_identity_seed(secret, b"group-A"))
                .expect("prepare A")
                .key_package_bytes(),
            "kp",
        )
        .expect("decode A");
        let kp_b: KeyPackage = decode(
            TreeKemMlsGroup::prepare_member(agent_id, &derive_identity_seed(secret, b"group-B"))
                .expect("prepare B")
                .key_package_bytes(),
            "kp",
        )
        .expect("decode B");
        assert_ne!(
            kp_a.verifying_key, kp_b.verifying_key,
            "signing keys must differ across groups"
        );
        assert_ne!(
            kp_a.agreement_key, kp_b.agreement_key,
            "KEM keys must differ across groups"
        );
        assert_ne!(
            kp_a.credential, kp_b.credential,
            "credentials (which embed the MemberId) must differ across groups"
        );
    }

    #[test]
    fn duplicate_add_is_rejected() {
        // Adding the same agent twice must be refused — saorsa-mls would
        // otherwise create a second orphaned leaf for the same agent.
        let mut alice = TreeKemMlsGroup::create(b"g".to_vec(), agent(1), &seed(1)).expect("create");
        let bob_id = agent(2);
        let bob = TreeKemMlsGroup::prepare_member(bob_id, &seed(2)).expect("prepare");
        let kp = bob.key_package_bytes().to_vec();
        alice.add_member(bob_id, &kp).expect("first add ok");

        let bob2 = TreeKemMlsGroup::prepare_member(bob_id, &seed(2)).expect("prepare again");
        let err = alice
            .add_member(bob_id, bob2.key_package_bytes())
            .unwrap_err();
        assert!(matches!(err, MlsError::MlsOperation(_)));
        assert_eq!(
            alice.member_count(),
            2,
            "duplicate add must not grow the tree"
        );
    }

    #[test]
    fn verified_remove_uses_roster_keypackage_not_stale_leaf_map() {
        let alice_id = agent(1);
        let bob_id = agent(2);
        let carol_id = agent(3);
        let mut alice = TreeKemMlsGroup::create(b"verified-remove".to_vec(), alice_id, &seed(1))
            .expect("create");
        let bob = TreeKemMlsGroup::prepare_member(bob_id, &seed(2)).expect("bob prepare");
        let bob_kp = bob.key_package_bytes().to_vec();
        alice.add_member(bob_id, &bob_kp).expect("add bob");
        let carol = TreeKemMlsGroup::prepare_member(carol_id, &seed(3)).expect("carol prepare");
        let carol_kp = carol.key_package_bytes().to_vec();
        alice.add_member(carol_id, &carol_kp).expect("add carol");
        let bob_leaf = alice.agent_to_leaf[&bob_id];
        let carol_leaf = alice.agent_to_leaf[&carol_id];
        alice.agent_to_leaf.insert(bob_id, carol_leaf);
        alice.agent_to_leaf.insert(carol_id, bob_leaf);

        let remove_commit = alice
            .remove_member_verified(bob_id, &bob_kp)
            .expect("roster KeyPackage must resolve Bob's real leaf despite stale map");
        assert!(!remove_commit.is_empty());
        assert_eq!(alice.member_count(), 2);
        assert!(
            alice.remove_member_verified(carol_id, &carol_kp).is_ok(),
            "Carol must still be removable after Bob, proving the stale map did not remove her"
        );
    }

    #[test]
    fn remove_unknown_member_errors_cleanly() {
        let mut g = TreeKemMlsGroup::create(b"room".to_vec(), agent(1), &seed(1)).expect("create");
        let err = g.remove_member(agent(9)).unwrap_err();
        assert!(matches!(err, MlsError::MemberNotInGroup(_)));
    }
}
