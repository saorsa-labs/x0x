//! CRDT-backed key-value store for x0x agents.
//!
//! Provides a replicated key-value store using OR-Set for key membership,
//! LWW-Register semantics for values, and delta-based synchronization
//! over the gossip network.
//!
//! ## Usage
//!
//! ```ignore
//! // Create a new store
//! let handle = agent.create_kv_store("My Store", "my-store-topic").await?;
//!
//! // Put a value
//! handle.put("greeting", b"hello world", "text/plain").await?;
//!
//! // Get a value
//! if let Some(entry) = handle.get("greeting").await? {
//!     println!("{}", String::from_utf8_lossy(&entry.value));
//! }
//!
//! // List keys
//! let keys = handle.keys().await?;
//! ```

pub mod delta;
pub mod entry;
pub mod error;
pub mod store;
pub mod sync;

pub use delta::KvStoreDelta;
pub use entry::KvEntry;
pub use error::{KvError, Result};
pub use store::{AccessPolicy, KvStore, KvStoreId};
pub use sync::KvStoreSync;
