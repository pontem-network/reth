use move_executor::types::state_store::state_value::{
    StateValue as AptosStateValue, StateValueMetadata,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct ValueWithMeta {
    pub(crate) value: Vec<u8>,
    pub(crate) metadata: Option<StateValueMetadata>,
}

impl From<ValueWithMeta> for AptosStateValue {
    fn from(value: ValueWithMeta) -> AptosStateValue {
        if let Some(metadata) = value.metadata {
            AptosStateValue::new_with_metadata(value.value, metadata)
        } else {
            AptosStateValue::new_legacy(value.value)
        }
    }
}
