use std::str::FromStr;

use crate::{
    database::StateProviderDatabase,
    lumio::{
        coin::{extract_balance, native_coin_store, MasterOfCoin},
        mapper::map_account_address,
        value::ValueWithMeta,
    },
    processor::tests::StateProviderTest,
};
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
use reth_primitives::{Account, Address, U256};
use serde::{Deserialize, Serialize};

#[test]
fn test_extract_balance() {
    check("0", 0);
    check("13131313", 0);
    check("1313131335", 0);
    check("13131313356", 1);
    check("131313133569", 13);
    check("1313131335697", 131);
    check("13121313356972", 1312);
    check("131213133569723", 13121);
    check("1312131335697234", 131213);
    check("13121313356972345", 1312131);
    check("131213133569723456", 13121313);
    check("1000000000000000000", 100000000);
    check("12345678901443434434", 1234567890);
    check("1234567812345678901443434434", 123456781234567890);
    check("41234567812345678901443434434", 1000000000000000000);
    check("1234567890144343443412345678901443434434", 1000000000000000000);
    check("123456789014434344341234567890144343443412345678901443434434", 1000000000000000000);

    fn check(balance: &str, expected: u64) {
        let balance = extract_balance(U256::from_str(balance).unwrap());
        assert_eq!(balance, expected);
    }
}

#[test]
fn test_master_of_coin_is_native_coin() {
    let master_of_coin = MasterOfCoin::default();
    assert!(master_of_coin.is_coin_access(&native_state_key(AccountAddress::random())));
    assert!(master_of_coin.is_coin_access(&native_state_key(AccountAddress::ZERO)));
    assert!(master_of_coin.is_coin_access(&native_state_key(AccountAddress::ONE)));

    assert!(!master_of_coin.is_coin_access(&StateKey::new(StateKeyInner::AccessPath(
        AccessPath::resource_access_path(
            AccountAddress::ONE,
            StructTag {
                address: AccountAddress::ONE,
                module: ident_str!("coin").to_owned(),
                name: ident_str!("CoinStore").to_owned(),
                type_params: vec![TypeTag::Struct(Box::new(StructTag {
                    address: AccountAddress::ONE,
                    module: ident_str!("apt_coin").to_owned(),
                    name: ident_str!("AptCoin").to_owned(),
                    type_params: vec![],
                }))],
            }
        )
        .unwrap(),
    ))));

    assert!(!master_of_coin.is_coin_access(&StateKey::new(StateKeyInner::AccessPath(
        AccessPath::resource_access_path(
            AccountAddress::ONE,
            StructTag {
                address: AccountAddress::ONE,
                module: ident_str!("coin").to_owned(),
                name: ident_str!("CoinStore").to_owned(),
                type_params: vec![TypeTag::Struct(Box::new(StructTag {
                    address: AccountAddress::ONE,
                    module: ident_str!("eth_coin").to_owned(),
                    name: ident_str!("ethCoin").to_owned(),
                    type_params: vec![],
                }))],
            }
        )
        .unwrap(),
    ))));
}

#[test]
fn test_master_of_coin_apply_eth_balance_no_acc() {
    let master_of_coin = MasterOfCoin::default();
    let db = StateProviderTest::default();

    let mut db = StateProviderDatabase::new(db);
    let addr = map_account_address(AccountAddress::random());
    let value = encode_coin_store(&CoinStore::new(0));
    assert!(master_of_coin.apply_native_balance(addr, value, &mut db).is_err());
}

#[test]
fn test_master_of_coin_apply_eth_balance() {
    let mut db = StateProviderTest::default();
    let alice = map_account_address(AccountAddress::random());
    db.insert_account(
        alice,
        Account { nonce: 0, balance: U256::from(13421798), bytecode_hash: None },
        None,
        Default::default(),
    );
    let bob = map_account_address(AccountAddress::random());
    db.insert_account(
        bob,
        Account { nonce: 0, balance: U256::ZERO, bytecode_hash: None },
        None,
        Default::default(),
    );
    let mut db = StateProviderDatabase::new(db);
    let coins = MasterOfCoin::default();
    perform_test(
        &coins,
        &mut db,
        alice,
        |balance| {
            assert_eq!(balance.unwrap(), 0);
            Some(0)
        },
        Some(U256::from(13421798)),
    );

    perform_test(
        &coins,
        &mut db,
        bob,
        |balance| {
            assert_eq!(balance.unwrap(), 0);
            Some(1)
        },
        Some(U256::from(10_000_000_000_u64)),
    );

    perform_test(
        &coins,
        &mut db,
        bob,
        |balance| {
            assert_eq!(balance.unwrap(), 1);
            Some(10)
        },
        Some(U256::from(100_000_000_000_u64)),
    );

    perform_test(
        &coins,
        &mut db,
        alice,
        |balance| {
            assert_eq!(balance.unwrap(), 0);
            Some(1_000_000_000)
        },
        Some(U256::from(10000000000013421798u64)),
    );

    perform_test(
        &coins,
        &mut db,
        alice,
        |balance| {
            assert_eq!(balance.unwrap(), 1000000000);
            Some(0)
        },
        Some(U256::from(13421798u64)),
    );

    perform_test(
        &coins,
        &mut db,
        alice,
        |balance| {
            assert_eq!(balance.unwrap(), 0);
            Some(0)
        },
        Some(U256::from(13421798u64)),
    );

    perform_test(
        &coins,
        &mut db,
        bob,
        |balance| {
            assert_eq!(balance.unwrap(), 10);
            Some(100)
        },
        Some(U256::from(100) * U256::from(10000000000u64)),
    );

    perform_test(
        &coins,
        &mut db,
        bob,
        |balance| {
            assert_eq!(balance.unwrap(), 100);
            Some(u64::MAX)
        },
        Some(U256::from(u64::MAX) * U256::from(10000000000u64)),
    );

    perform_test(
        &coins,
        &mut db,
        bob,
        |balance| {
            assert_eq!(balance.unwrap(), 1000000000000000000);
            Some(1000000000000000000)
        },
        Some(U256::from_str("184467440737095516150000000000").unwrap()),
    );

    perform_test(
        &coins,
        &mut db,
        bob,
        |balance| {
            assert_eq!(balance.unwrap(), 1000000000000000000);
            Some(2000000000000000000)
        },
        Some(U256::from_str("194467440737095516150000000000").unwrap()),
    );

    perform_test(
        &coins,
        &mut db,
        bob,
        |balance| {
            assert_eq!(balance.unwrap(), 1000000000000000000);
            Some(0)
        },
        Some(U256::from_str("184467440737095516150000000000").unwrap()),
    );

    let mut expected = U256::from_str("174467440737095516150000000000").unwrap();
    for _ in 0..17 {
        perform_test(
            &coins,
            &mut db,
            bob,
            |balance| {
                assert_eq!(balance.unwrap(), 1000000000000000000);
                Some(0)
            },
            Some(expected),
        );
        expected -= U256::from_str("10000000000000000000000000000").unwrap();
    }

    perform_test(
        &coins,
        &mut db,
        bob,
        |balance| {
            assert_eq!(balance.unwrap(), 1000000000000000000);
            Some(0)
        },
        Some(U256::from_str("4467440737095516150000000000").unwrap()),
    );

    perform_test(
        &coins,
        &mut db,
        bob,
        |balance| {
            assert_eq!(balance.unwrap(), 446744073709551615);
            Some(0)
        },
        Some(U256::from_str("0").unwrap()),
    );

    fn perform_test(
        coins: &MasterOfCoin,
        db: &mut StateProviderDatabase<StateProviderTest>,
        acc: Address,
        act: impl FnOnce(Option<u64>) -> Option<u64>,
        balance: Option<U256>,
    ) {
        let value = encode_coin_store(&CoinStore::new_random());
        let value = coins
            .apply_native_balance(acc, value, db.clone())
            .ok()
            .map(|val| decode_coin_store(&val));
        if let Some(result) = act(value.clone().map(|val| val.coin.value)) {
            let mut coin: CoinStore = value.unwrap_or_else(|| CoinStore::new(result));
            coin.coin.value = result;
            let value = encode_coin_store(&coin);
            let balance_diff = coins.calculate_coin_diff(
                acc,
                &ValueWithMeta { value: value.into_bytes(), metadata: None },
            );

            let acc = db.load_account(acc).unwrap();
            acc.balance = balance_diff.apply(acc.balance);
            assert_eq!(
                acc.balance,
                balance.unwrap(),
                "balance mismatch:{}!={}",
                acc.balance,
                balance.unwrap()
            );
        } else {
            assert!(balance.is_none());
        }
        coins.reset();
    }
}

pub(crate) fn native_state_key(addr: AccountAddress) -> StateKey {
    StateKey::new(StateKeyInner::AccessPath(
        AccessPath::resource_access_path(addr, native_coin_store()).unwrap(),
    ))
}

pub(crate) fn encode_coin_store(coin_store: &CoinStore) -> StateValue {
    StateValue::new_legacy(bcs::to_bytes(coin_store).unwrap())
}

pub(crate) fn decode_coin_store(value: &StateValue) -> CoinStore {
    bcs::from_bytes(value.bytes()).unwrap()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CoinStore {
    coin: Coin,
    frozen: bool,
    deposit_events: EventHandle,
    withdraw_events: EventHandle,
}

impl CoinStore {
    pub(crate) fn new(balance: u64) -> Self {
        Self {
            coin: Coin { value: balance },
            frozen: false,
            deposit_events: EventHandle::default(),
            withdraw_events: EventHandle::default(),
        }
    }

    pub(crate) fn new_random() -> Self {
        Self {
            coin: Coin { value: 0 },
            frozen: rand::random::<bool>(),
            deposit_events: EventHandle {
                counter: rand::random::<u64>(),
                guid: Guid {
                    id: ID { creation_num: rand::random::<u64>(), addr: AccountAddress::random() },
                },
            },
            withdraw_events: EventHandle {
                counter: rand::random::<u64>(),
                guid: Guid {
                    id: ID { creation_num: rand::random::<u64>(), addr: AccountAddress::random() },
                },
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Coin {
    /// Amount of coin this address has.
    value: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Default)]
pub(crate) struct EventHandle {
    /// Total number of events emitted to this event stream.
    counter: u64,
    /// A globally unique ID for this event stream.
    guid: Guid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Default)]
/// A globally unique identifier derived from the sender's address and a counter
pub(crate) struct Guid {
    id: ID,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
/// A non-privileged identifier that can be freely created by anyone. Useful for looking up GUID's.
pub(crate) struct ID {
    /// If creation_num is `i`, this is the `i+1`th GUID created by `addr`
    creation_num: u64,
    /// Address that created the GUID
    addr: AccountAddress,
}

impl Default for ID {
    fn default() -> Self {
        Self { creation_num: 0, addr: AccountAddress::ONE }
    }
}
