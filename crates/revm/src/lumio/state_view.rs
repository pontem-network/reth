use std::cell::RefCell;

use super::{
    coin::MasterOfCoin, mapper::map_access_path_to_address, preloader::AccountPreloader,
    resource::ResourceIO, value::ValueWithMeta,
};
use anyhow::Error;
use move_executor::{
    state_view::TStateView,
    types::{
        executable::ModulePath,
        state_store::{
            state_key::StateKey, state_storage_usage::StateStorageUsage, state_value::StateValue,
        },
    },
};
use revm::Database;

pub(crate) struct EthStorageAdapter<'state, DB> {
    storage: RefCell<DB>,
    master_of_coin: &'state MasterOfCoin,
    preloader: &'state AccountPreloader,
}

impl<'state, DB> EthStorageAdapter<'state, DB>
where
    DB: Database,
    DB::Error: std::fmt::Display,
{
    pub(crate) fn new(
        storage: DB,
        master_of_coin: &'state MasterOfCoin,
        preloader: &'state AccountPreloader,
    ) -> Self {
        Self { storage: RefCell::new(storage), master_of_coin, preloader }
    }
}

impl<'state, DB> TStateView for EthStorageAdapter<'state, DB>
where
    DB: Database,
    DB::Error: std::fmt::Display,
{
    type Key = StateKey;

    fn get_state_value(&self, state_key: &Self::Key) -> anyhow::Result<Option<StateValue>> {
        let mut store = self.storage.borrow_mut();
        if let Some(module_path) = state_key.module_path() {
            let bytecode_hash = store
                .basic(map_access_path_to_address(&module_path))
                .map_err(|err| Error::msg(err.to_string()))?
                .map(|account| account.code_hash);
            Ok(match bytecode_hash {
                Some(hash) => {
                    let code =
                        store.code_by_hash(hash).map_err(|err| Error::msg(err.to_string()))?;
                    let value: Option<Result<ValueWithMeta, _>> = (!code.is_empty())
                        .then(|| code.bytes())
                        .map(|bytes| bcs::from_bytes(bytes));
                    match value {
                        Some(val) => {
                            let val = dbg!(val).map_err(Error::msg)?;
                            Some(val.into())
                        }
                        None => None,
                    }
                }
                None => None,
            })
        } else {
            let mut io: ResourceIO<'_, DB> =
                ResourceIO::new(state_key, &mut *store, self.preloader)?;
            let value = io.read_state_value()?;

            if let Some(value) = value {
                if self.master_of_coin.is_coin_access(state_key) {
                    let value = self.master_of_coin.apply_native_balance(
                        io.address(),
                        value,
                        &mut *store,
                    )?;
                    Ok(Some(value))
                } else {
                    Ok(Some(value))
                }
            } else {
                Ok(None)
            }
        }
    }

    fn get_usage(&self) -> anyhow::Result<StateStorageUsage> {
        Ok(StateStorageUsage::Untracked)
    }
}
