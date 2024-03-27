use std::cell::RefCell;

use anyhow::Error;
use move_core_types::{
    account_address::AccountAddress,
    ident_str,
    language_storage::{StructTag, TypeTag},
};
use move_executor::types::{
    access_path::AccessPath,
    state_store::{
        state_key::{StateKey, StateKeyInner},
        state_value::StateValue,
    },
};
use reth_primitives::{Address, U256};
use revm::{primitives::HashMap, Database};

use super::value::ValueWithMeta;

pub(crate) struct MasterOfCoin {
    native_coin: Vec<u8>,
    cache: RefCell<HashMap<Address, AccountState>>,
}

impl MasterOfCoin {
    pub(crate) fn new() -> Self {
        Self {
            native_coin: AccessPath::resource_path_vec(native_coin_store())
                .expect("expected eth coin valid path"),
            cache: RefCell::new(HashMap::new()),
        }
    }

    pub(crate) fn reset(&self) {
        self.cache.borrow_mut().clear();
    }

    pub(crate) fn is_coin_access(&self, key: &StateKey) -> bool {
        match key.inner() {
            StateKeyInner::AccessPath(ap) => ap.path == self.native_coin,
            StateKeyInner::TableItem { .. } => false,
            StateKeyInner::Raw(_) => false,
        }
    }

    pub(crate) fn apply_native_balance<DB>(
        &self,
        address: Address,
        mut value: StateValue,
        mut db: DB,
    ) -> Result<StateValue, Error>
    where
        DB: Database,
        DB::Error: std::fmt::Display,
    {
        let mut cache = self.cache.borrow_mut();
        let move_balance = if let Some(state) = cache.get(&address).copied() {
            state.move_balance
        } else {
            let acc = db
                .basic(address)
                .map_err(|err| Error::msg(err.to_string()))?
                .ok_or_else(|| Error::msg("account not found"))?;
            let move_balance = extract_balance(acc.balance);
            cache.insert(address, AccountState { move_balance });
            move_balance
        };
        let encoded_balance = move_balance.to_le_bytes();
        let value_bytes = value.as_mut_bytes();
        value_bytes[..encoded_balance.len()].copy_from_slice(&encoded_balance);
        Ok(value)
    }

    pub(crate) fn calculate_coin_diff(
        &self,
        acc_address: Address,
        value: &ValueWithMeta,
    ) -> BalanceDiff {
        let cache = self.cache.borrow();
        let original_state = cache.get(&acc_address).copied().unwrap_or_default();

        let value_bytes = value.value.as_slice();
        let mut move_balance = [0u8; 8];
        move_balance.copy_from_slice(&value_bytes[..8]);
        let move_balance = u64::from_le_bytes(move_balance);
        if move_balance > original_state.move_balance {
            BalanceDiff::Increase(
                U256::from(move_balance - original_state.move_balance) * U256::from(PRECISION_DIFF),
            )
        } else {
            BalanceDiff::Decrease(
                U256::from(original_state.move_balance - move_balance) * U256::from(PRECISION_DIFF),
            )
        }
    }
}

impl Default for MasterOfCoin {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct AccountState {
    move_balance: u64,
}

#[derive(Debug, Clone)]
pub(crate) enum BalanceDiff {
    Increase(U256),
    Decrease(U256),
}

impl BalanceDiff {
    pub(crate) fn apply(&self, balance: U256) -> U256 {
        match self {
            BalanceDiff::Increase(diff) => balance + diff,
            BalanceDiff::Decrease(diff) => balance - diff,
        }
    }
}

const ETH_DECIMALS: u32 = 18;
const APT_DECIMALS: u32 = 8;

const MAX_APTOS_COIN_CAPACITY: u64 = 10u64.pow(APT_DECIMALS + 10);

const PRECISION_DIFF: u64 = 10u64.pow(ETH_DECIMALS - APT_DECIMALS);

pub(crate) fn extract_balance(balance: U256) -> u64 {
    let eth_with_apt_decimals = balance / U256::from(PRECISION_DIFF);
    let max_copacity = U256::from(MAX_APTOS_COIN_CAPACITY);
    if eth_with_apt_decimals / max_copacity > U256::ZERO {
        MAX_APTOS_COIN_CAPACITY
    } else {
        (eth_with_apt_decimals % U256::from(MAX_APTOS_COIN_CAPACITY)).to()
    }
}

pub(crate) fn native_coin_store() -> StructTag {
    StructTag {
        address: AccountAddress::ONE,
        module: ident_str!("coin").to_owned(),
        name: ident_str!("CoinStore").to_owned(),
        type_params: vec![TypeTag::Struct(Box::new(native_coin_tag()))],
    }
}

pub(crate) fn native_coin_tag() -> StructTag {
    StructTag {
        address: AccountAddress::ONE,
        module: ident_str!("native_coin").to_owned(),
        name: ident_str!("NativeCoin").to_owned(),
        type_params: vec![],
    }
}
