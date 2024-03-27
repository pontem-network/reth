//! Error types emitted by types or implementations of this crate.

use reth_interfaces::{provider::ProviderError, RethError};
use reth_primitives::{revm_primitives::EVMError, B256};
use reth_transaction_pool::{blobstore::OtherError, BlobStoreError};
use tokio::sync::oneshot;

/// Possible error variants during payload building.
#[derive(Debug, thiserror::Error)]
pub enum PayloadBuilderError {
    /// Thrown whe the parent block is missing.
    #[error("missing parent block {0}")]
    MissingParentBlock(B256),
    /// An oneshot channels has been closed.
    #[error("sender has been dropped")]
    ChannelClosed,
    /// Error occurring in the blob store.
    #[error(transparent)]
    BlobStore(#[from] BlobStoreError),
    /// Other internal error
    #[error(transparent)]
    Internal(#[from] RethError),
    /// Unrecoverable error during evm execution.
    #[error("evm execution error: {0}")]
    EvmExecutionError(EVMError<ProviderError>),
    /// Thrown if the payload requests withdrawals before Shanghai activation.
    #[error("withdrawals set before Shanghai activation")]
    WithdrawalsBeforeShanghai,
    /// Any other payload building errors.
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync>),
    /* ------LUMIO-START------- */
    /// Magic specific payload building errors.
    #[cfg(feature = "optimism")]
    #[error(transparent)]
    Magic(#[from] MagicPayloadBuilderError),
    /* ------LUMIO-END------- */
}

/* ------LUMIO-START------- */
impl Clone for PayloadBuilderError {
    fn clone(&self) -> Self {
        match self {
            Self::MissingParentBlock(arg0) => Self::MissingParentBlock(arg0.clone()),
            Self::ChannelClosed => Self::ChannelClosed,
            Self::BlobStore(arg0) => Self::BlobStore(arg0.clone()),
            Self::Internal(arg0) => Self::Internal(arg0.clone()),
            Self::EvmExecutionError(arg0) => Self::EvmExecutionError(arg0.clone()),
            Self::WithdrawalsBeforeShanghai => Self::WithdrawalsBeforeShanghai,
            Self::Other(arg0) => Self::Other(Box::new(OtherError::new(arg0))),
            Self::Magic(arg0) => Self::Magic(arg0.clone()),
        }
    }
}
/* ------LUMIO-END------- */

impl PayloadBuilderError {
    /// Create a new error from a boxed error.
    pub fn other<E>(error: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        PayloadBuilderError::Other(Box::new(error))
    }
}

impl From<ProviderError> for PayloadBuilderError {
    fn from(error: ProviderError) -> Self {
        PayloadBuilderError::Internal(RethError::Provider(error))
    }
}

/* ------LUMIO-START------- */
/// Magic specific payload building errors.
#[cfg(feature = "optimism")]
#[derive(Debug, thiserror::Error, Clone)]
pub enum MagicPayloadBuilderError {
    /// Thrown when one of the cross-vm calls fails.
    #[error("failed to execute cross-vm call")]
    CrossVMCallFail,
}
/* ------LUMIO-END------- */

impl From<oneshot::error::RecvError> for PayloadBuilderError {
    fn from(_: oneshot::error::RecvError) -> Self {
        PayloadBuilderError::ChannelClosed
    }
}
