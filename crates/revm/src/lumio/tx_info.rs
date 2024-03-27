use move_core_types::vm_status::VMStatus;
use move_executor::types::{
    contract_event::ContractEvent,
    state_store::state_key::StateKey,
    transaction::{Transaction, TransactionStatus},
    write_set::WriteOp,
};
use reth_interfaces::executor::BlockExecutionError;
use serde::{Deserialize, Serialize};

/// Block info.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockInfo {
    timestamp: u64,
    epoch: u64,
    height: u64,
    transactions: Vec<TransactionInfo>,
    chain_id: u32,
}

impl BlockInfo {
    /// Create a new block info.
    pub fn new(timestamp: u64, epoch: u64, height: u64, chain_id: u32) -> Self {
        Self { timestamp, epoch, height, transactions: vec![], chain_id }
    }

    /// Add a transaction info.
    pub fn add_transaction(&mut self, transaction: TransactionInfo) {
        self.transactions.push(transaction);
    }

    /// Encode the block info.
    pub fn encode(&self) -> Result<Vec<u8>, BlockExecutionError> {
        bcs::to_bytes(self).map_err(|_| BlockExecutionError::ProviderError)
    }
}

/// Transaction info.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionInfo {
    tx: Transaction,
    version: u64,
    status: VMStatus,
    events: Vec<ContractEvent>,
    write_set: Vec<(StateKey, WriteOp)>,
    gas_used: u64,
    tx_status: TransactionStatus,
}

impl TransactionInfo {
    /// Create a new transaction info.
    pub fn new(
        tx: Transaction,
        version: u64,
        status: VMStatus,
        events: Vec<ContractEvent>,
        write_set: Vec<(StateKey, WriteOp)>,
        gas_used: u64,
        tx_status: TransactionStatus,
    ) -> Self {
        Self { tx, status, events, write_set, gas_used, tx_status, version }
    }

    /// Merge two transaction infos into one.
    pub fn merge(&mut self, other: Self) {
        self.events.extend(other.events);
        self.write_set.extend(other.write_set);
        self.gas_used += other.gas_used;
    }
}
