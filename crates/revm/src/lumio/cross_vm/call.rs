use alloy_primitives::Address;
use alloy_sol_types::{
    sol_data::{Address as AbiAddress, Bytes as AbiBytes},
    SolType,
};
use move_core_types::{
    account_address::AccountAddress,
    identifier::Identifier,
    language_storage::{ModuleId, TypeTag},
    parser::parse_type_tags,
};
use reth_interfaces::executor::BlockExecutionError;
use reth_primitives::alloy_primitives::Bytes as AlloyBytes;
use serde::Deserialize;

type CrossEventType = (AbiAddress, AbiBytes, AbiBytes, AbiBytes, AbiBytes, AbiBytes);

/// Cross VM call event data
#[derive(Deserialize, Debug)]
pub struct EthCallEventData {
    /// Ethereum address
    pub eth_address: Vec<u8>,
    /// Ethereum calldata
    pub eth_calldata: Vec<u8>,
    /// Move address
    pub move_address: AccountAddress,
}

/// Cross VM call
#[derive(Debug)]
pub enum CrossVmCall {
    /// Ethereum call
    Eth(EthCallEventData),
    /// Move call
    Move(AlloyBytes),
}

/// Cross VM move call
#[derive(Debug)]
pub struct CrossEthEvent {
    /// Ethereum address
    pub contract_address: Address,
    /// Module id
    pub module_id: ModuleId,
    /// Move function name
    pub function_name: Identifier,
    /// Move call data
    pub call_data: Vec<u8>,
    /// Move generics
    pub generics: Vec<TypeTag>,
}

impl CrossEthEvent {
    /// Decode cross VM call event
    pub fn decode(log: &[u8]) -> Result<CrossEthEvent, BlockExecutionError> {
        let (contract_address, module_address, module_name, function_id, call_data, generics) =
            CrossEventType::abi_decode_sequence(log, true).unwrap();

        let module_addr = AccountAddress::from_bytes(module_address).map_err(|e| {
            BlockExecutionError::CanonicalRevert {
                inner: format!("[CrossVM]: failed to decode module address {}", e),
            }
        })?;
        let module_name = Identifier::from_utf8(module_name).map_err(|e| {
            BlockExecutionError::CanonicalRevert {
                inner: format!("[CrossVM]: failed to decode module name {}", e),
            }
        })?;
        let function_name = Identifier::from_utf8(function_id).map_err(|e| {
            BlockExecutionError::CanonicalRevert {
                inner: format!("[CrossVM]: failed to decode function name {}", e),
            }
        })?;

        let module_id = ModuleId::new(module_addr, module_name);

        let generics = if !generics.is_empty() {
            parse_type_tags(&String::from_utf8_lossy(&generics)).map_err(|e| {
                BlockExecutionError::CanonicalRevert {
                    inner: format!("[CrossVM]: failed to decode generics {}", e),
                }
            })?
        } else {
            vec![]
        };

        Ok(CrossEthEvent { contract_address, module_id, function_name, call_data, generics })
    }
}
