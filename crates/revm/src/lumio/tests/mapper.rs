use crate::lumio::mapper::{map_access_path_to_address, map_account_address};
use hex_literal::hex;
use move_core_types::account_address::AccountAddress;
use move_executor::{crypto::hash::CryptoHash, types::access_path::AccessPath};
use reth_primitives::Address;

#[test]
fn test_map_account_address() {
    let address = AccountAddress::random();
    let result = map_account_address(address);
    assert_eq!(result, Address::from_slice(&address.as_ref()[12..]));
}

#[test]
fn test_map_access_path_to_address() {
    let path = AccessPath::new(AccountAddress::random(), hex!("48656c6c6f20776f726c6421").to_vec());
    let addr = map_access_path_to_address(&path);
    assert_eq!(&CryptoHash::hash(&path).as_ref()[12..], addr.as_slice());
}
