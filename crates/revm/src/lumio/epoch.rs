use move_core_types::{account_address::AccountAddress, ident_str, language_storage::StructTag};
use move_executor::{
    state_view::TStateView,
    types::{access_path::AccessPath, state_store::state_key::StateKey},
};
use once_cell::sync::Lazy;
use reth_interfaces::executor::BlockExecutionError;
use tracing::error;

static EPOCH_PATH: Lazy<StateKey> = Lazy::new(|| {
    StateKey::access_path(
        AccessPath::resource_access_path(
            AccountAddress::ONE,
            StructTag {
                address: AccountAddress::ONE,
                module: ident_str!("reconfiguration").to_owned(),
                name: ident_str!("Configuration").to_owned(),
                type_params: vec![],
            },
        )
        .expect("Failed to create epoch access path"),
    )
});

/// Epoch holder.
#[derive(Default, Debug)]
pub struct Epoch {
    /// Current epoch.
    pub epoch: u64,
}

impl Epoch {
    /// Loads epoch from state view.
    pub fn init_epoch(
        &mut self,
        state_view: impl TStateView<Key = StateKey>,
    ) -> Result<bool, BlockExecutionError> {
        let state_value = state_view.get_state_value(&EPOCH_PATH).map_err(|err| {
            error!(target: "move", "Failed to load epoch:{:?}", err);
            BlockExecutionError::ProviderError
        })?;

        if let Some(state_value) = state_value {
            self.epoch = bcs::from_bytes(&state_value.bytes()[..8])
                .map_err(|_| BlockExecutionError::ProviderError)?;
            Ok(true)
        } else {
            self.epoch = 0;
            Ok(false)
        }
    }
}
