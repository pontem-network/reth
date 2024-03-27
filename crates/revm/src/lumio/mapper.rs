use move_core_types::account_address::AccountAddress as MoveAddress;
use move_executor::{crypto::hash::CryptoHash, types::access_path::AccessPath};
use reth_primitives::Address as EthAddress;

pub(crate) fn map_access_path_to_address(path: &AccessPath) -> EthAddress {
    let hash = CryptoHash::hash(path);
    EthAddress::from_slice(&hash.as_ref()[12..])
}

pub(crate) fn map_account_address(address: MoveAddress) -> EthAddress {
    let mut result = [0u8; 20];
    result.copy_from_slice(&address.as_slice()[12..]);
    EthAddress::from(result)
}

#[allow(missing_docs)]
pub fn map_account_address_to_move(address: EthAddress) -> MoveAddress {
    let mut new_address_bytes = [0u8; 32];
    new_address_bytes[12..].copy_from_slice(address.as_slice());

    MoveAddress::from(new_address_bytes)
}
