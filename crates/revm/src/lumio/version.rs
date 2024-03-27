use std::fmt::Display;

use move_core_types::{account_address::AccountAddress, ident_str, language_storage::StructTag};
use move_executor::{
    state_view::TStateView,
    types::{access_path::AccessPath, state_store::state_key::StateKey, write_set::WriteOp},
};
use once_cell::sync::Lazy;
use reth_interfaces::executor::BlockExecutionError;
use revm::Database;
use serde::{Deserialize, Serialize};

use super::state_view::EthStorageAdapter;

static KEY: Lazy<StateKey> = Lazy::new(|| {
    StateKey::access_path(
        AccessPath::resource_access_path(
            AccountAddress::ONE,
            StructTag {
                address: AccountAddress::ONE,
                module: ident_str!("transaction_info").to_owned(),
                name: ident_str!("Version").to_owned(),
                type_params: vec![],
            },
        )
        .expect("Failed to create access path for resource index"),
    )
});

#[derive(Debug, Serialize, Deserialize, Default)]
/// VersionHolder is a helper struct to manage the version of the transaction.
pub(crate) struct VersionHolder {
    version: u64,
    is_init: bool,
}

impl VersionHolder {
    /// Is the version initialized?
    pub(crate) fn is_init(&self) -> bool {
        self.is_init
    }

    /// make diff for the version
    pub(crate) fn make_write_op(&self) -> (&StateKey, WriteOp) {
        (
            &KEY,
            WriteOp::Modification(
                bcs::to_bytes(&Version::from(self)).expect("Failed to serialize"),
            ),
        )
    }

    /// Load the version from the storage.
    pub(crate) fn load<'state, DB>(
        &mut self,
        state_view: &'state EthStorageAdapter<'state, DB>,
    ) -> Result<(), BlockExecutionError>
    where
        DB: Database,
        DB::Error: Display,
    {
        if self.is_init() {
            panic!("Version already initialized");
        }

        self.is_init = true;
        let resource = state_view
            .get_state_value(&KEY)
            .map_err(|_| BlockExecutionError::ProviderError)?
            .and_then(|state_value| bcs::from_bytes::<Version>(state_value.bytes()).ok())
            .unwrap_or_default();
        self.version = resource.version;
        Ok(())
    }

    /// Return the next version.
    pub(crate) fn next_version(&mut self) -> u64 {
        if !self.is_init() {
            panic!("Version not initialized");
        }
        let version = self.version;
        self.version += 1;
        version
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct Version {
    version: u64,
}

impl From<&VersionHolder> for Version {
    fn from(holder: &VersionHolder) -> Self {
        Self { version: holder.version }
    }
}
