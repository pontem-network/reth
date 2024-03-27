use std::{
    fs,
    path::{Path, PathBuf},
};

use alloy_rlp::Decodable;
use clap::Args;
use reth_primitives::TransactionSigned;
use reth_transaction_pool::EthPooledTransaction;

/// Lumio args.
#[derive(Debug, Args, PartialEq, Default, Clone)]
#[clap(next_help_heading = "Lumio")]
pub struct LumioArgs {
    /// Path to the genesis update transaction
    #[clap(long)]
    pub genesis_update: Option<PathBuf>,
}

/// Load genesis update transaction.
pub(crate) fn load_genesis_update(
    genesis_update: &Path,
) -> eyre::Result<Option<EthPooledTransaction>> {
    if !genesis_update.exists() {
        return Ok(None);
    }
    let tx = fs::read(genesis_update)?;
    let encoded_len = tx.len();
    let tx = TransactionSigned::decode(&mut tx.as_slice())?
        .into_ecrecovered()
        .ok_or(eyre::eyre!("failed to recover tx"))?;
    fs::remove_file(genesis_update)?;
    Ok(Some(EthPooledTransaction::new(tx, encoded_len)))
}
