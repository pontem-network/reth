use crate::{
    database::StateProviderDatabase,
    lumio::{
        preloader::AccountPreloader,
        resource::{KeysIter, ResourceIO, ValueSplitter},
        value::ValueWithMeta,
    },
    primitives::HashMap,
};
use move_core_types::account_address::AccountAddress;
use move_executor::types::{
    access_path::AccessPath,
    state_store::state_key::{StateKey, StateKeyInner},
};
use reth_primitives::{Address, StorageKey, StorageValue, B256, U256};
use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
use revm::primitives::StorageSlot;

fn hash(str: &str) -> U256 {
    U256::from_limbs(bytemuck::cast(B256::from_slice(&hex::decode(str).unwrap()).0))
}

fn data(str: &str) -> Vec<u8> {
    hex::decode(str).unwrap()
}

#[test]
fn test_key_iter() {
    let mut iter =
        KeysIter::new(hash("0000000000000000000000000000000000000000000000000000000000000000"), 0);
    assert_eq!(iter.next(), None);

    let mut iter =
        KeysIter::new(hash("0000000000000000000000000000000000000000000000000000000000000000"), 10);
    assert_eq!(
        iter.next(),
        Some((hash("0000000000000000000000000000000000000000000000000000000000000000"), 4..14))
    );
    assert_eq!(iter.next(), None);

    let mut iter =
        KeysIter::new(hash("0000000000000000000000000000000000000000000000000000000000000000"), 28);
    assert_eq!(
        iter.next(),
        Some((hash("0000000000000000000000000000000000000000000000000000000000000000"), 4..32))
    );
    assert_eq!(iter.next(), None);

    let mut iter =
        KeysIter::new(hash("0000000000000000000000000000000000000000000000000000000000000000"), 29);
    assert_eq!(
        iter.next(),
        Some((hash("0000000000000000000000000000000000000000000000000000000000000000"), 4..32))
    );
    assert_eq!(
        iter.next(),
        Some((hash("0100000000000000000000000000000000000000000000000000000000000000"), 0..1))
    );
    assert_eq!(iter.next(), None);

    let mut iter = KeysIter::new(
        hash("0000000000000000000000000000000000000000000000000000000000000000"),
        113,
    );
    assert_eq!(
        iter.next(),
        Some((hash("0000000000000000000000000000000000000000000000000000000000000000"), 4..32))
    ); // 28
    assert_eq!(
        iter.next(),
        Some((hash("0100000000000000000000000000000000000000000000000000000000000000"), 0..32))
    ); // 28 + 32 = 60
    assert_eq!(
        iter.next(),
        Some((hash("0200000000000000000000000000000000000000000000000000000000000000"), 0..32))
    ); // 60 + 32 = 92
    assert_eq!(
        iter.next(),
        Some((hash("0300000000000000000000000000000000000000000000000000000000000000"), 0..21))
    ); // 92 + 21 = 113
    assert_eq!(iter.next(), None);

    let mut iter = KeysIter::new(
        hash("FE00000000000000000000000000000000000000000000000000000000000000"),
        124,
    );
    assert_eq!(
        iter.next(),
        Some((hash("FE00000000000000000000000000000000000000000000000000000000000000"), 4..32))
    ); // 28
    assert_eq!(
        iter.next(),
        Some((hash("FF00000000000000000000000000000000000000000000000000000000000000"), 0..32))
    ); // 28 + 32 = 60
    assert_eq!(
        iter.next(),
        Some((hash("0001000000000000000000000000000000000000000000000000000000000000"), 0..32))
    ); // 60 + 32 = 92
    assert_eq!(
        iter.next(),
        Some((hash("0101000000000000000000000000000000000000000000000000000000000000"), 0..32))
    ); // 92 + 32 = 124
    assert_eq!(iter.next(), None);

    let mut iter = KeysIter::new(
        hash("FDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
        125,
    );
    assert_eq!(
        iter.next(),
        Some((hash("FDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), 4..32))
    ); // 28
    assert_eq!(
        iter.next(),
        Some((hash("FEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), 0..32))
    ); // 28 + 32 = 60
    assert_eq!(
        iter.next(),
        Some((hash("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), 0..32))
    ); // 60 + 32 = 92
    assert_eq!(
        iter.next(),
        Some((hash("0100000000000000000000000000000000000000000000000000000000000000"), 0..32))
    ); // 92 + 32 = 124
    assert_eq!(
        iter.next(),
        Some((hash("0200000000000000000000000000000000000000000000000000000000000000"), 0..1))
    ); // 124 + 1 = 125
    assert_eq!(iter.next(), None);
}

#[test]
fn test_value_splitter() {
    let mut val = data("");
    let mut iter = ValueSplitter::new(
        hash("00000000000000000000000000000000000000000000000000000000000000FD"),
        &val,
    );
    assert_eq!(iter.next(), None);

    val = data("42");
    let mut iter = ValueSplitter::new(
        hash("00000000000000000000000000000000000000000000000000000000000000FD"),
        &val,
    );
    assert_eq!(
        iter.next(),
        Some((
            hash("00000000000000000000000000000000000000000000000000000000000000FD"),
            hash("0100000042000000000000000000000000000000000000000000000000000000")
        ))
    );
    assert_eq!(iter.next(), None);

    val = data("0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C");
    let mut iter = ValueSplitter::new(
        hash("00000000000000000000000000000000000000000000000000000000000000FD"),
        &val,
    );
    assert_eq!(
        iter.next(),
        Some((
            hash("00000000000000000000000000000000000000000000000000000000000000FD"),
            hash("1c0000000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C")
        ))
    );
    assert_eq!(iter.next(), None);

    val = data("0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728");
    let mut iter = ValueSplitter::new(
        hash("FD00000000000000000000000000000000000000000000000000000000000000"),
        &val,
    );
    assert_eq!(
        iter.next(),
        Some((
            hash("FD00000000000000000000000000000000000000000000000000000000000000"),
            hash("280000000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C")
        ))
    );
    assert_eq!(
        iter.next(),
        Some((
            hash("FE00000000000000000000000000000000000000000000000000000000000000"),
            hash("1d1e1f2021222324252627280000000000000000000000000000000000000000")
        ))
    );
    assert_eq!(iter.next(), None);
}

#[test]
fn test_resource_io() {
    let provider = MockEthProvider::default();
    store(&provider, "0x1", "path_1", "TestData");
    assert_eq!(load(&provider, "0x1", "path_1"), "TestData".as_bytes().to_vec());
    delete(&provider, "0x1", "path_1");
    assert_eq!(load(&provider, "0x1", "path_1"), Vec::<u8>::new());

    store(&provider, "0x2", "path_1", "TestData_2");
    store(&provider, "0x1", "path_1", "TestData_1");

    assert_eq!(load(&provider, "0x1", "path_1"), "TestData_1".as_bytes().to_vec());
    assert_eq!(load(&provider, "0x2", "path_1"), "TestData_2".as_bytes().to_vec());

    delete(&provider, "0x1", "path_1");
    assert_eq!(load(&provider, "0x1", "path_1"), Vec::<u8>::new());
    assert_eq!(load(&provider, "0x2", "path_1"), "TestData_2".as_bytes().to_vec());

    delete(&provider, "0x2", "path_1");
    assert_eq!(load(&provider, "0x1", "path_1"), Vec::<u8>::new());

    let mut long_data =
        "This is a way too long string to fit into a single storage slot".to_string();
    for _ in 0..1000 {
        long_data.push_str("This is a way too long string to fit into a single storage slot");
    }

    store(&provider, "0x13", "path_13", long_data.as_str());
    assert_eq!(load(&provider, "0x13", "path_13"), long_data.as_bytes().to_vec());
    store(&provider, "0x13", "path_13", "TestData_13");
    assert_eq!(load(&provider, "0x13", "path_13"), "TestData_13".as_bytes().to_vec());
    delete(&provider, "0x13", "path_13");
    assert_eq!(load(&provider, "0x13", "path_13"), Vec::<u8>::new());
}

fn load(provider: &MockEthProvider, acc: &str, path: &str) -> Vec<u8> {
    let path =
        AccessPath::new(AccountAddress::from_hex_literal(acc).unwrap(), path.as_bytes().to_vec());
    let key = StateKey::new(StateKeyInner::AccessPath(path));
    let mut substate = StateProviderDatabase::new(provider);
    let preloader = AccountPreloader::default();
    let mut io = ResourceIO::new(&key, &mut substate, &preloader).unwrap();
    let val = io.read_state_value().unwrap();
    val.map(|val| val.into_bytes()).unwrap_or_default()
}

fn delete(provider: &MockEthProvider, acc: &str, path: &str) {
    let path =
        AccessPath::new(AccountAddress::from_hex_literal(acc).unwrap(), path.as_bytes().to_vec());
    let key = StateKey::new(StateKeyInner::AccessPath(path));
    let mut substate = StateProviderDatabase::new(provider);
    let preloader = AccountPreloader::default();

    let mut io = ResourceIO::new(&key, &mut substate, &preloader).unwrap();
    let addr = io.address();
    let mut diff = HashMap::new();
    io.delete_value(&mut diff).unwrap();
    apply_storage(&diff, provider, addr);
    let mut io = ResourceIO::new(&key, &mut substate, &preloader).unwrap();
    let val = io.read_state_value().unwrap();
    assert!(val.map(|v| v.into_bytes()).unwrap_or_default().is_empty());
}

fn store(provider: &MockEthProvider, acc: &str, path: &str, data: &str) {
    let data = data.as_bytes().to_vec();
    let path =
        AccessPath::new(AccountAddress::from_hex_literal(acc).unwrap(), path.as_bytes().to_vec());
    let key = StateKey::new(StateKeyInner::AccessPath(path));
    let mut substate = StateProviderDatabase::new(provider);
    let preloader = AccountPreloader::default();
    let mut io = ResourceIO::new(&key, &mut substate, &preloader).unwrap();
    let addr = io.address();
    let mut diff = HashMap::new();
    let value = ValueWithMeta { value: data, metadata: None };
    io.modify_value(&value, &mut diff).unwrap();
    apply_storage(&diff, provider, addr);
    let mut io = ResourceIO::new(&key, &mut substate, &preloader).unwrap();
    let val = io.read_state_value().unwrap();
    assert_eq!(val.unwrap().into_bytes(), value.value);
}

fn apply_storage(storage: &HashMap<U256, StorageSlot>, provider: &MockEthProvider, addr: Address) {
    let mut map = provider.accounts.lock();
    let acc = map.entry(addr).or_insert(ExtendedAccount::new(0, U256::ZERO));

    let diff = storage.iter().map(|(key, slot)| {
        let key = StorageKey::from(*key);
        let value = StorageValue::from(slot.present_value);
        (key, value)
    });
    acc.update_storage(diff);
}
