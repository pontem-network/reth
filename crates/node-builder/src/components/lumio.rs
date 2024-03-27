use std::path::Path;

use alloy_rlp::Decodable;
use reth_primitives::TransactionSigned;
use reth_primitives::FromRecoveredTransaction;
use reth_transaction_pool::TransactionPool;
use reth_tracing::tracing::{warn, info};

/// Load genesis update transaction.
async fn load_genesis_update<T: FromRecoveredTransaction>(
    genesis_update: &Path,
) -> eyre::Result<Option<T>> {
    if !genesis_update.exists() {
        return Ok(None);
    }
    let tx = tokio::fs::read(genesis_update).await?;
    let tx = TransactionSigned::decode(&mut tx.as_slice())?
        .into_ecrecovered()
        .ok_or_else(|| eyre::eyre!("failed to recover tx"))?;
    tokio::fs::remove_file(genesis_update).await?;
    Ok(Some(T::from_recovered_transaction(tx)))
}

pub(crate) async fn handle_genesis_update<P>(genesis_update: Option<&impl AsRef<Path>>, pool: P) -> eyre::Result<()>
where
    P: TransactionPool + Send + Sync + 'static,
{
    if let Some(genesis_update) = genesis_update.map(AsRef::as_ref) {
        info!(target: "reth::cli", "Genesis update provided: {:?}", genesis_update);
        if let Some(genesis_update) = load_genesis_update(genesis_update).await? {
            pool.add_transaction_unchecked(
                reth_transaction_pool::TransactionOrigin::Local,
                genesis_update,
            )
            .await?;
            info!(target: "reth::cli", "Genesis update added to txpool");
        } else {
            warn!(target: "reth::cli", "Genesis update provided but not found");
        }
    }
    Ok(())
}
