//! The KMS the control plane wraps secret-version DEKs with (S2 design decisions 3 and 4).
//!
//! [`ls_envelope::KeyWrapper`] is not dyn-compatible (it returns `impl Future`), so
//! [`DekWrapper`] is the object-safe form [`crate::app::AppState`] holds. Every
//! `KeyWrapper + Send + Sync` is a `DekWrapper`. The control plane only ever wraps: its
//! OpenBao token is encrypt-only by policy, and this trait has no unwrap.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use ls_envelope::{
    BaoToken, Binding, DataKey, KeyWrapper, OpenBaoTransit, WrapError, WrapKeyId, WrappedDek,
};
use secrecy::ExposeSecret;

use crate::config::KmsConfig;

/// The future [`DekWrapper::wrap`] returns.
pub type WrapFuture<'a> = Pin<Box<dyn Future<Output = Result<WrappedDek, WrapError>> + Send + 'a>>;

/// Wraps a version's DEK with the gateway's KMS key. Wrap only: the control plane cannot unwrap.
pub trait DekWrapper: Send + Sync {
    fn wrap<'a>(&'a self, dek: &'a DataKey, binding: &'a Binding) -> WrapFuture<'a>;
}

impl<T: KeyWrapper + Send + Sync> DekWrapper for T {
    fn wrap<'a>(&'a self, dek: &'a DataKey, binding: &'a Binding) -> WrapFuture<'a> {
        Box::pin(KeyWrapper::wrap(self, dek, binding))
    }
}

/// Build the OpenBao transit wrapper from configuration. The token is copied once into
/// [`BaoToken`] (zeroized on drop). Errors carry no address or token.
pub fn openbao(config: &KmsConfig) -> Result<Arc<dyn DekWrapper>, WrapError> {
    let key = WrapKeyId::new(&config.key, config.key_version)?;
    let token = BaoToken::new(config.token.expose_secret().to_owned());
    Ok(Arc::new(OpenBaoTransit::new(&config.addr, key, token)?))
}
