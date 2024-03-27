#![allow(clippy::mutable_key_type)]
use crate::lumio::{
    preloader::AccountPreloader,
    resource::{map_storage_key_to_eth, ResourceIO},
    value::ValueWithMeta,
};
use anyhow::Result;
use move_core_types::{
    account_address::AccountAddress, identifier::Identifier, language_storage::StructTag,
};
use move_executor::types::{access_path::AccessPath, state_store::state_key::StateKey};
use once_cell::sync::Lazy;
use reth_primitives::Address;
use revm::{
    primitives::{Account, HashMap},
    Database,
};
use std::collections::BTreeSet;

static RESOURCE_LIST_TAG: Lazy<StructTag> = Lazy::new(|| StructTag {
    address: AccountAddress::ONE,
    module: Identifier::new("resource_info").unwrap(),
    name: Identifier::new("Resources").unwrap(),
    type_params: vec![],
});

pub(crate) struct ResourceMap {
    resources: HashMap<AccountAddress, BTreeSet<StateKey>>,
}

impl ResourceMap {
    pub(crate) fn new() -> Self {
        Self { resources: HashMap::new() }
    }

    pub(crate) fn insert<DB>(
        &mut self,
        account_address: AccountAddress,
        state_key: StateKey,
        db: &mut DB,
        preloader: &AccountPreloader,
    ) -> Result<()>
    where
        DB: Database,
        DB::Error: std::fmt::Display,
    {
        match self.resources.get_mut(&account_address) {
            Some(set) => {
                set.insert(state_key);
            }
            None => {
                let mut set_from_storage =
                    self.get_resource_list(account_address, db, preloader)?;
                set_from_storage.insert(state_key);
                self.resources.insert(account_address, set_from_storage);
            }
        }
        Ok(())
    }

    pub(crate) fn remove<DB>(
        &mut self,
        account_address: AccountAddress,
        state_key: &StateKey,
        db: &mut DB,
        preloader: &AccountPreloader,
    ) -> Result<()>
    where
        DB: Database,
        DB::Error: std::fmt::Display,
    {
        match self.resources.get_mut(&account_address) {
            Some(set) => {
                set.remove(state_key);
            }
            None => {
                let mut set_from_storage =
                    self.get_resource_list(account_address, db, preloader)?;
                set_from_storage.remove(state_key);
                self.resources.insert(account_address, set_from_storage);
            }
        }
        Ok(())
    }

    fn get_resource_list<DB>(
        &self,
        addr: AccountAddress,
        db: &mut DB,
        preloader: &AccountPreloader,
    ) -> Result<BTreeSet<StateKey>>
    where
        DB: Database,
        DB::Error: std::fmt::Display,
    {
        let access_path = AccessPath::resource_access_path(addr, RESOURCE_LIST_TAG.clone())?;
        let state_key = StateKey::access_path(access_path);
        let mut io = ResourceIO::new(&state_key, db, preloader)?;

        match io.read_state_value()? {
            Some(set) => Ok(bcs::from_bytes(set.bytes())?),
            None => Ok(BTreeSet::new()),
        }
    }
}

pub(crate) fn map_resource_list<DB>(
    resource_map: ResourceMap,
    state: &mut HashMap<Address, Account>,
    db: &mut DB,
    preloader: &AccountPreloader,
) -> Result<()>
where
    DB: Database,
    DB::Error: std::fmt::Display,
{
    for (addr, key_set) in resource_map.resources.into_iter() {
        let access_path = AccessPath::resource_access_path(addr, RESOURCE_LIST_TAG.clone())?;
        let state_key = StateKey::access_path(access_path);
        let mut io = ResourceIO::new(&state_key, db, preloader)?;
        let eth_addr = map_storage_key_to_eth(&state_key)?.0;
        let acc = state.get_mut(&eth_addr).expect("unreachable");
        let storage: &mut HashMap<
            reth_primitives::ruint::Uint<256, 4>,
            revm::primitives::StorageSlot,
        > = &mut acc.storage;
        io.modify_value(
            &ValueWithMeta { value: bcs::to_bytes(&key_set)?, metadata: None },
            storage,
        )?;
    }
    Ok(())
}
