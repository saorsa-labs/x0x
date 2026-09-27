//! [`NoteKv`] over a live group [`crate::KvStoreHandle`].

use super::error::NoteError;
use super::store::{KvFuture, NoteKv};
use crate::error::IdentityError;
use crate::KvStoreHandle;

fn map_error(error: IdentityError) -> NoteError {
    match error {
        IdentityError::Unauthorized(message) => NoteError::Forbidden(message),
        other => NoteError::Store(other.to_string()),
    }
}

impl NoteKv for KvStoreHandle {
    fn store_id(&self) -> KvFuture<'_, [u8; 32]> {
        Box::pin(async move { Ok(self.store_id_bytes().await) })
    }

    fn entries(&self, prefix: String) -> KvFuture<'_, Vec<(String, Vec<u8>)>> {
        Box::pin(async move {
            Ok(self
                .keys()
                .await
                .map_err(map_error)?
                .into_iter()
                .filter(|entry| entry.key.starts_with(&prefix))
                .map(|entry| (entry.key, entry.value))
                .collect())
        })
    }

    fn get(&self, key: String) -> KvFuture<'_, Option<Vec<u8>>> {
        Box::pin(async move {
            Ok(KvStoreHandle::get(self, &key)
                .await
                .map_err(map_error)?
                .map(|entry| entry.value))
        })
    }

    fn put(&self, key: String, value: Vec<u8>, content_type: &'static str) -> KvFuture<'_, bool> {
        Box::pin(async move {
            let outcome = self
                .put_with_outcome(key, value, content_type.to_string())
                .await
                .map_err(map_error)?;
            Ok(outcome.published)
        })
    }

    fn image_len(&self) -> KvFuture<'_, u64> {
        Box::pin(async move { self.retained_image_len().await.map_err(map_error) })
    }
}
