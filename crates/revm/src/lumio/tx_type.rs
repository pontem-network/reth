use std::ops::Deref;

use anyhow::Error;
use move_core_types::{
    identifier::Identifier,
    language_storage::{ModuleId, TypeTag},
};
use move_executor::types::{
    state_store::state_key::StateKey,
    transaction::{SignedTransaction as MoveSignedTransaction, WriteSetPayload},
};
use reth_primitives::{Address, TransactionSigned, TxHash, U256};
use revm::primitives::HashMap;
use serde::{Deserialize, Serialize};
use tracing::debug;

const MOVE_TX_PREFIX: &[u8] = b"MOVE";
const MOVE_GENESIS_PREFIX: &[u8] = b"MOGS";
const MOVE_RESOURCE_PREFIX: &[u8] = b"MVRV";
const MOVE_VIEW_PREFIX: &[u8] = b"MVVF";
const MOVE_SIMULATED_PREFIX: &[u8] = b"MVSM";

/// Transaction type that can be either Move or EVM.
#[derive(Debug)]
pub enum MagicTx<'a> {
    /// EVM transaction.
    Eth(&'a TransactionSigned),
    /// Move transaction.
    Move(LumioExtension, &'a TransactionSigned),
}

impl<'a> MagicTx<'a> {
    /// Check if transaction is move tx.
    pub fn is_move(&self) -> bool {
        matches!(self, MagicTx::Move(_, _))
    }

    /// payload of the transaction.
    pub fn payload(&self) -> &[u8] {
        if self.is_move() {
            &self.eth_tx().input().as_ref()[MOVE_TX_PREFIX.len()..]
        } else {
            self.eth_tx().input().as_ref()
        }
    }

    fn eth_tx(&self) -> &TransactionSigned {
        match self {
            MagicTx::Eth(tx) => tx,
            MagicTx::Move(_, tx) => tx,
        }
    }

    /// Get tx hash.
    pub fn hash(&self) -> TxHash {
        self.eth_tx().hash
    }
}

impl Deref for MagicTx<'_> {
    fn deref(&self) -> &Self::Target {
        self.eth_tx()
    }

    type Target = TransactionSigned;
}

impl<'a> From<&'a TransactionSigned> for MagicTx<'a> {
    fn from(tx: &'a TransactionSigned) -> Self {
        fn decode_magic_tx(tx: &TransactionSigned) -> Result<MagicTx<'_>, Error> {
            let input = tx.input();
            Ok(match LumioTxType::from(tx) {
                LumioTxType::Genesis => MagicTx::Move(
                    LumioExtension::Genesis(bcs::from_bytes(&input[MOVE_GENESIS_PREFIX.len()..])?),
                    tx,
                ),
                LumioTxType::MoveTransaction => MagicTx::Move(
                    LumioExtension::Signed(bcs::from_bytes(&input[MOVE_TX_PREFIX.len()..])?),
                    tx,
                ),
                LumioTxType::Eth => MagicTx::Eth(tx),
            })
        }
        decode_magic_tx(tx).unwrap_or_else(|_| MagicTx::Eth(tx))
    }
}

/// Transaction type that can be either Move resource or Move function call.
#[derive(Debug)]
pub enum MagicView {
    /// Move resource.
    Resource(Resource),
    /// Move function call.
    ViewCall(ViewCall),
    /// Simulated transaction.
    Simulated(MoveSignedTransaction),
}

/// Move resource.
#[derive(Serialize, Deserialize, Debug)]
pub struct Resource {
    /// State key representing resource.
    pub key: StateKey,
}

/// Move function call.
#[derive(Serialize, Deserialize, Debug)]
pub struct ViewCall {
    /// Module id.
    pub module_id: ModuleId,
    /// Function name.
    pub func_name: Identifier,
    /// Type arguments.
    pub type_args: Vec<TypeTag>,
    /// Function arguments.
    pub arguments: Vec<Vec<u8>>,
    /// Gas budget.
    pub gas_budget: u64,
}

impl TryFrom<&[u8]> for MagicView {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.starts_with(MOVE_RESOURCE_PREFIX) {
            let resource = bcs::from_bytes(&bytes[MOVE_RESOURCE_PREFIX.len()..])?;
            Ok(MagicView::Resource(resource))
        } else if bytes.starts_with(MOVE_VIEW_PREFIX) {
            let view_call = bcs::from_bytes(&bytes[MOVE_VIEW_PREFIX.len()..])?;
            debug!("ViewCall successfully deserialized: {:#?}", view_call);
            Ok(MagicView::ViewCall(view_call))
        } else if bytes.starts_with(MOVE_SIMULATED_PREFIX) {
            let move_tx = bcs::from_bytes(&bytes[MOVE_SIMULATED_PREFIX.len()..])?;
            Ok(MagicView::Simulated(move_tx))
        } else {
            debug!("Not a MagicView");
            Err(anyhow::anyhow!("Invalid magic view"))
        }
    }
}

/// Move transaction type.
#[derive(Debug)]
pub enum LumioExtension {
    /// Move signed transaction.
    Signed(MoveSignedTransaction),
    /// Move genesis transaction.
    Genesis(LumioGenesisUpdate),
}

///Update genesis transaction.
#[derive(Debug, Serialize, Deserialize)]
pub struct LumioGenesisUpdate {
    /// Genesis payload.
    pub payload: WriteSetPayload,
    /// Ethereum contracts.
    pub eth_contracts: Vec<LumioAlloc>,
}

/// Lumio alloc.
#[derive(Debug, Serialize, Deserialize)]
pub struct LumioAlloc {
    /// Address.
    pub address: Address,
    /// Contract.
    pub contract: Vec<u8>,
    /// Storage.
    pub storage: HashMap<U256, U256>,
}

impl LumioExtension {
    /// Encode move transaction.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        Ok(match self {
            LumioExtension::Signed(tx) => {
                let tx = bcs::to_bytes(tx)?;
                [MOVE_TX_PREFIX, &tx].concat()
            }
            LumioExtension::Genesis(payload) => {
                let payload = bcs::to_bytes(payload)?;
                [MOVE_GENESIS_PREFIX, &payload].concat()
            }
        })
    }
}

/// Lumio transaction type.
#[derive(Debug)]
pub enum LumioTxType {
    /// Move genesis transaction.
    Genesis,
    /// Move transaction.
    MoveTransaction,
    /// EVM transaction.
    Eth,
}

impl From<&TransactionSigned> for LumioTxType {
    fn from(tx: &TransactionSigned) -> Self {
        LumioTxType::from((tx.to(), tx.input().as_ref()))
    }
}

impl From<(Option<Address>, &[u8])> for LumioTxType {
    fn from((to, tx): (Option<Address>, &[u8])) -> Self {
        if to.is_some() || tx.len() < 4 {
            return LumioTxType::Eth;
        }

        match &tx[0..4] {
            MOVE_TX_PREFIX => LumioTxType::MoveTransaction,
            MOVE_GENESIS_PREFIX => LumioTxType::Genesis,
            _ => LumioTxType::Eth,
        }
    }
}
