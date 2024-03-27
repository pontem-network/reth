use reth_primitives::B256;
mod call;
mod function;
mod rt;
pub use call::*;
pub use function::*;
use once_cell::sync::Lazy;
use reth_primitives::Address;
pub use rt::*;

pub(crate) static CROSS_VM_ETH_ADDR: Lazy<Address> =
    Lazy::new(|| "0x42000000000000000000000000000000000000ff".parse().expect("Invalid address"));

pub(crate) static CROSS_VM_MV_ADDR: Lazy<Address> =
    Lazy::new(|| "0x0000000000000000000000000000000000000001".parse().expect("Invalid address"));

pub(crate) static CROSS_VM_ETH_TOPIC: Lazy<B256> = Lazy::new(|| {
    "0xb1ee1c34db66e83584533a490e5cca83973604a6511b9c72c2d018d9ed9b1fad"
        .parse()
        .expect("Invalid topic")
});

pub(crate) static CROSS_VM_MV_TOPIC: Lazy<B256> = Lazy::new(|| {
    "0x64f273725c56a151b02d06f3391189ce0b819bb537919e3362e1a2348da5c95a"
        .parse()
        .expect("Invalid topic")
});

#[cfg(test)]
mod tests {
    use crate::lumio::cross_vm::CROSS_VM_MV_TOPIC;
    use alloy_primitives::B256;
    use aptos_types::contract_event::ContractEvent;

    use move_core_types::account_address::AccountAddress;

    use aptos_types::{event::EventKey, HashValue};
    use move_core_types::{
        identifier::Identifier,
        language_storage::{StructTag, TypeTag},
    };

    #[test]
    fn test_check_move_topic() {
        let event_key = EventKey::new(5, AccountAddress::ONE);
        let event = ContractEvent::new(
            event_key,
            0,
            TypeTag::Struct(Box::from(StructTag {
                address: AccountAddress::ONE,
                module: Identifier::new("evm").unwrap(),
                name: Identifier::new("CallEvent").unwrap(),
                type_params: vec![],
            })),
            vec![],
        );
        let topic = B256::from(
            HashValue::keccak256_of(event.type_tag().to_canonical_string().as_bytes()).bytes(),
        );
        assert_eq!(*CROSS_VM_MV_TOPIC, topic);
    }
}
