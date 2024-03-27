use crate::processor::{compare_receipts_root_and_logs_bloom, EVMProcessor};
use reth_interfaces::executor::{
    BlockExecutionError, BlockValidationError, OptimismBlockExecutionError,
};
use reth_node_api::ConfigureEvm;
use reth_primitives::{
    proofs::calculate_receipt_root_optimism, revm_primitives::ResultAndState, BlockWithSenders,
    Bloom, ChainSpec, Hardfork, Receipt, ReceiptWithBloom, TxType, B256, U256,
};
use reth_provider::{BlockExecutor, BundleStateWithReceipts};
use revm::DatabaseCommit;
use std::time::Instant;
use tracing::{debug, error, trace};

/* ------LUMIO-START------- */
use crate::{
    lumio::{
        cross_vm,
        mapper::map_account_address_to_move,
        tx_info::BlockInfo,
        tx_type::{LumioExtension, MagicTx},
    },
    primitives::ExecutionResult,
};
use reth_primitives::{lumio::LumioBlockInfo, revm::env::fill_tx_env};
/* ------LUMIO-END------- */

/// Verify the calculated receipts root against the expected receipts root.
pub fn verify_receipt_optimism<'a>(
    expected_receipts_root: B256,
    expected_logs_bloom: Bloom,
    receipts: impl Iterator<Item = &'a Receipt> + Clone,
    chain_spec: &ChainSpec,
    timestamp: u64,
) -> Result<(), BlockExecutionError> {
    // Calculate receipts root.
    let receipts_with_bloom = receipts.map(|r| r.clone().into()).collect::<Vec<ReceiptWithBloom>>();
    let receipts_root =
        calculate_receipt_root_optimism(&receipts_with_bloom, chain_spec, timestamp);

    // Create header log bloom.
    let logs_bloom = receipts_with_bloom.iter().fold(Bloom::ZERO, |bloom, r| bloom | r.bloom);

    compare_receipts_root_and_logs_bloom(
        receipts_root,
        logs_bloom,
        expected_receipts_root,
        expected_logs_bloom,
    )?;

    Ok(())
}

impl<'a, EvmConfig> BlockExecutor for EVMProcessor<'a, EvmConfig>
where
    EvmConfig: ConfigureEvm,
{
    type Error = BlockExecutionError;

    fn execute(
        &mut self,
        block: &BlockWithSenders,
        total_difficulty: U256,
    ) -> Result<(), BlockExecutionError> {
        let receipts = self.execute_inner(block, total_difficulty)?;
        //self.save_receipts(receipts)
        /* ------LUMIO-START------- */
        self.save_receipts(receipts.0, receipts.1)
        /* ------LUMIO-END------- */
    }

    fn execute_and_verify_receipt(
        &mut self,
        block: &BlockWithSenders,
        total_difficulty: U256,
    ) -> Result<(), BlockExecutionError> {
        // execute block
        //let receipts = self.execute_inner(block, total_difficulty)?;
        /* ------LUMIO-START------- */
        let (receipts, block_info) = self.execute_inner(block, total_difficulty)?;
        /* ------LUMIO-END------- */

        // TODO Before Byzantium, receipts contained state root that would mean that expensive
        // operation as hashing that is needed for state root got calculated in every
        // transaction This was replaced with is_success flag.
        // See more about EIP here: https://eips.ethereum.org/EIPS/eip-658
        if self.chain_spec.fork(Hardfork::Byzantium).active_at_block(block.header.number) {
            let time = Instant::now();
            if let Err(error) = verify_receipt_optimism(
                block.header.receipts_root,
                block.header.logs_bloom,
                receipts.iter(),
                self.chain_spec.as_ref(),
                block.timestamp,
            ) {
                debug!(target: "evm", %error, ?receipts, "receipts verification failed");
                return Err(error)
            };
            self.stats.receipt_root_duration += time.elapsed();
        }

        self.save_receipts(
            receipts,   /* ------LUMIO-START------- */
            block_info, /* ------LUMIO-END------- */
        )
    }

    fn execute_transactions(
        &mut self,
        block: &BlockWithSenders,
        total_difficulty: U256,
    ) -> Result<
        (
            Vec<Receipt>,
            u64,
            /* ------LUMIO-START------- */ LumioBlockInfo, /* ------LUMIO-END------- */
        ),
        BlockExecutionError,
    > {
        self.init_env(&block.header, total_difficulty);
        /* ------LUMIO-START------- */
        let number = block.header.number;
        let timestamp = block.header.timestamp;
        let mut block_info = BlockInfo::new(timestamp, self.mv.epoch(), number, self.mv.chain_id());
        /* ------LUMIO-END------- */

        // perf: do not execute empty blocks
        if block.body.is_empty() {
            return Ok((
                Vec::new(),
                0,
                /* ------LUMIO-START------- */
                LumioBlockInfo { number, block_info: block_info.encode()? }, /* ------LUMIO-END------- */
            ));
        }

        /* ------LUMIO-START------- */
        let mut log = if self.mv.check_framework(&mut self.evm.context.evm.db)? {
            let (ResultAndState { result, state }, tx_info) =
                self.mv.new_block(number, timestamp, &mut self.evm.context.evm.db)?;
            if !result.is_success() {
                return Err(BlockExecutionError::CanonicalCommit {
                    inner: format!("Failed to create block:{:?}", result),
                });
            }
            block_info.add_transaction(tx_info);
            self.db_mut().original_db.commit(state);
            result.into_logs()
        } else {
            error!(target: "evm", "Move framework is not initialized.");
            Vec::new()
        };
        /* ------LUMIO-END------- */

        let is_regolith =
            self.chain_spec.fork(Hardfork::Regolith).active_at_timestamp(block.timestamp);

        // Ensure that the create2deployer is force-deployed at the canyon transition. Optimism
        // blocks will always have at least a single transaction in them (the L1 info transaction),
        // so we can safely assume that this will always be triggered upon the transition and that
        // the above check for empty blocks will never be hit on OP chains.
        super::ensure_create2_deployer(self.chain_spec().clone(), block.timestamp,/*------LUMIO-START-------*/&mut /*------LUMIO-END-------*/self.db_mut()/*------LUMIO-START-------*/.original_db/*------LUMIO-END-------*/)
            .map_err(|_| {
            BlockExecutionError::OptimismBlockExecution(
                OptimismBlockExecutionError::ForceCreate2DeployerFail,
            )
        })?;

        let mut cumulative_gas_used = 0;
        let mut receipts = Vec::with_capacity(block.body.len());
        for (sender, transaction) in block.transactions_with_sender() {
            let time = Instant::now();
            // The sum of the transaction’s gas limit, Tg, and the gas utilized in this block prior,
            // must be no greater than the block’s gasLimit.
            let block_available_gas = block.header.gas_limit - cumulative_gas_used;
            if transaction.gas_limit() > block_available_gas &&
                (is_regolith || !transaction.is_system_transaction())
            {
                return Err(BlockValidationError::TransactionGasLimitMoreThanAvailableBlockGas {
                    transaction_gas_limit: transaction.gas_limit(),
                    block_available_gas,
                }
                .into())
            }

            // An optimism block should never contain blob transactions.
            if matches!(transaction.tx_type(), TxType::Eip4844) {
                return Err(BlockExecutionError::OptimismBlockExecution(
                    OptimismBlockExecutionError::BlobTransactionRejected,
                ))
            }

            let mut deposit_tx = None;
            // Create new move account on L1 => L2 deposit tx.
            if transaction.is_deposit() {
                let recipient = transaction.to().unwrap();
                let gas_limit = transaction.gas_limit();
                let result = self.mv.create_move_account(
                    recipient,
                    gas_limit,
                    &mut self.evm.context.evm.db,
                )?;

                match result {
                    Some(res_and_state) => {
                        let (ResultAndState { result: _, state }, tx_info) = res_and_state;
                        deposit_tx = Some(tx_info);
                        // TODO: add test case where cross tx failed and check that deposit tx
                        // worked!
                        self.db_mut().original_db.commit(state);
                    }
                    None => {
                        // Do not commit state if account already exists.
                    }
                }
            };

            // Cache the depositor account prior to the state transition for the deposit nonce.
            //
            // Note that this *only* needs to be done post-regolith hardfork, as deposit nonces
            // were not introduced in Bedrock. In addition, regular transactions don't have deposit
            // nonces, so we don't need to touch the DB for those.
            let depositor = (is_regolith && transaction.is_deposit())
                .then(|| {
                    self.db_mut()
                        /* ------LUMIO-START------- */
                        .original_db
                        /* ------LUMIO-END------- */
                        .load_cache_account(*sender)
                        .map(|acc| acc.account_info().unwrap_or_default())
                })
                .transpose()
                .map_err(|_| BlockExecutionError::ProviderError)?;

            // Execute transaction.
            //let ResultAndState { result, state } = self.transact(transaction, *sender)?;
            /* ------LUMIO-START------- */
            let ResultAndState { mut result, mut state } = match MagicTx::from(transaction) {
                MagicTx::Eth(transaction) => self.transact(transaction, *sender)?,
                MagicTx::Move(LumioExtension::Signed(transaction), eth_tx) => {
                    let (tx_result, mut tx_info) =
                        self.mv.transact(transaction, *sender, &mut self.evm.context.evm.db)?;

                    if let Some(deposit_info) = deposit_tx {
                        tx_info.merge(deposit_info);
                    }

                    block_info.add_transaction(tx_info);

                    // Fill the evm env properly
                    let mut envelope_buf = Vec::with_capacity(eth_tx.length_without_header());
                    eth_tx.encode_enveloped(&mut envelope_buf);
                    fill_tx_env(&mut self.evm.context.evm.env.tx, eth_tx, *sender);

                    tx_result
                }
                MagicTx::Move(LumioExtension::Genesis(genesis), _) => {
                    let (tx_result, mut tx_info) =
                        self.mv.execute_genesis(genesis, &mut self.evm.context.evm.db)?;
                    if let Some(deposit_info) = deposit_tx {
                        tx_info.merge(deposit_info);
                    }
                    block_info.add_transaction(tx_info);

                    tx_result
                }
            };

            self.stats.execution_duration += time.elapsed();
            let time = Instant::now();

            self.db_mut().commit(state.clone());

            let signer = transaction
                .signature()
                .recover_signer(transaction.transaction.signature_hash())
                .unwrap_or_default();
            let mut gas_used = result.gas_used();

            // cross vm call handle
            let cross_result = dbg!(cross_vm::run_cross_calls(
                &result,
                &mut self.evm,
                &mut self.mv,
                transaction.gas_limit() - gas_used,
                map_account_address_to_move(signer),
            ));

            match cross_result {
                Ok(available_gas) => {
                    gas_used = transaction.gas_limit() - available_gas;
                    self.db_mut().finalize();
                }
                Err(err) => {
                    // redefine origin tx execution result
                    result = ExecutionResult::Revert {
                        gas_used,
                        output: err.to_string().into_bytes().into(),
                    };
                    state = Default::default();

                    self.db_mut().rollback();
                }
            }
            /* ------LUMIO-END------- */
            trace!(
                target: "evm",
                ?transaction, ?result, ?state,
                "Executed transaction"
            );
            self.stats.execution_duration += time.elapsed();
            let time = Instant::now();

            // self.db_mut().commit(state);
            /* ------LUMIO-START-------*//*------LUMIO-END------- */

            self.stats.apply_state_duration += time.elapsed();

            // append gas used
            //cumulative_gas_used += result.gas_used();
            /* ------LUMIO-START------- */
            cumulative_gas_used += gas_used;
            /* ------LUMIO-END------- */

            // Push transaction changeset and calculate header bloom filter for receipt.
            receipts.push(Receipt {
                tx_type: transaction.tx_type(),
                // Success flag was added in `EIP-658: Embedding transaction status code in
                // receipts`.
                success: result.is_success(),
                cumulative_gas_used,
                // convert to reth log
                logs: result
                    .into_logs()
                    .into_iter()
                    /* ------LUMIO-START------- */
                    .chain(std::mem::take(&mut log)) /* ------LUMIO-END------- */
                    .map(Into::into)
                    .collect(),
                #[cfg(feature = "optimism")]
                deposit_nonce: depositor.map(|account| account.nonce),
                // The deposit receipt version was introduced in Canyon to indicate an update to how
                // receipt hashes should be computed when set. The state transition process ensures
                // this is only set for post-Canyon deposit transactions.
                #[cfg(feature = "optimism")]
                deposit_receipt_version: (transaction.is_deposit() &&
                    self.chain_spec()
                        .is_fork_active_at_timestamp(Hardfork::Canyon, block.timestamp))
                .then_some(1),
            });
            /* ------LUMIO-START------- */
            self.mv.finalize(); /* ------LUMIO-END------- */
        }

        // Ok((receipts, cumulative_gas_used))
        /* ------LUMIO-START------- */
        let block_info = block_info.encode()?;
        Ok((receipts, cumulative_gas_used, LumioBlockInfo { number, block_info }))
        /* ------LUMIO-END------- */
    }

    fn take_output_state(&mut self) -> BundleStateWithReceipts {
        let receipts = std::mem::take(&mut self.receipts);
        /* ------LUMIO-START------- */
        let blocks = std::mem::take(&mut self.blocks);
        /* ------LUMIO-END------- */
        BundleStateWithReceipts::new(
            self.evm
                .context
                .evm
                .db /* ------LUMIO-START------- */
                .original_db /* ------LUMIO-END------- */
                .take_bundle(),
            receipts,
            self.first_block.unwrap_or_default(),
            /* ------LUMIO-START------- */ blocks, /* ------LUMIO-END------- */
        )
    }

    fn size_hint(&self) -> Option<usize> {
        Some(
            self.evm
                .context
                .evm
                .db /* ------LUMIO-START------- */
                .original_db /* ------LUMIO-END------- */
                .bundle_size_hint(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        database::StateProviderDatabase,
        test_utils::{StateProviderTest, TestEvmConfig},
    };
    use reth_primitives::{
        Account, Address, Block, ChainSpecBuilder, Header, Signature, StorageKey, StorageValue,
        Transaction, TransactionKind, TransactionSigned, TxEip1559, BASE_MAINNET,
    };
    use revm::L1_BLOCK_CONTRACT;
    use std::{collections::HashMap, str::FromStr, sync::Arc};

    fn create_op_state_provider() -> StateProviderTest {
        let mut db = StateProviderTest::default();

        let l1_block_contract_account =
            Account { balance: U256::ZERO, bytecode_hash: None, nonce: 1 };

        let mut l1_block_storage = HashMap::new();
        // base fee
        l1_block_storage.insert(StorageKey::with_last_byte(1), StorageValue::from(1000000000));
        // l1 fee overhead
        l1_block_storage.insert(StorageKey::with_last_byte(5), StorageValue::from(188));
        // l1 fee scalar
        l1_block_storage.insert(StorageKey::with_last_byte(6), StorageValue::from(684000));
        // l1 free scalars post ecotone
        l1_block_storage.insert(
            StorageKey::with_last_byte(3),
            StorageValue::from_str(
                "0x0000000000000000000000000000000000001db0000d27300000000000000005",
            )
            .unwrap(),
        );

        db.insert_account(L1_BLOCK_CONTRACT, l1_block_contract_account, None, l1_block_storage);

        db
    }

    fn create_op_evm_processor<'a>(
        chain_spec: Arc<ChainSpec>,
        db: StateProviderTest,
    ) -> EVMProcessor<'a, TestEvmConfig> {
        let mut executor = EVMProcessor::new_with_db(
            chain_spec,
            StateProviderDatabase::new(db),
            TestEvmConfig::default(),
        );
        executor.evm.context.evm.db.original_db.load_cache_account(L1_BLOCK_CONTRACT).unwrap();
        executor
    }

    #[test]
    fn op_deposit_fields_pre_canyon() {
        let header = Header {
            timestamp: 1,
            number: 1,
            gas_limit: 1_000_000,
            gas_used: 42_000,
            ..Header::default()
        };

        let mut db = create_op_state_provider();

        let addr = Address::ZERO;
        let account = Account { balance: U256::MAX, ..Account::default() };
        db.insert_account(addr, account, None, HashMap::new());

        let chain_spec =
            Arc::new(ChainSpecBuilder::from(&*BASE_MAINNET).regolith_activated().build());

        let tx = TransactionSigned::from_transaction_and_signature(
            Transaction::Eip1559(TxEip1559 {
                chain_id: chain_spec.chain.id(),
                nonce: 0,
                gas_limit: 21_000,
                to: TransactionKind::Call(addr),
                ..Default::default()
            }),
            Signature::default(),
        );

        let tx_deposit = TransactionSigned::from_transaction_and_signature(
            Transaction::Deposit(reth_primitives::TxDeposit {
                from: addr,
                to: TransactionKind::Call(addr),
                gas_limit: 21_000,
                ..Default::default()
            }),
            Signature::default(),
        );

        let mut executor = create_op_evm_processor(chain_spec, db);

        // Attempt to execute a block with one deposit and one non-deposit transaction
        executor
            .execute(
                &BlockWithSenders {
                    block: Block {
                        header,
                        body: vec![tx, tx_deposit],
                        ommers: vec![],
                        withdrawals: None,
                    },
                    senders: vec![addr, addr],
                },
                U256::ZERO,
            )
            .unwrap();

        let tx_receipt = executor.receipts[0][0].as_ref().unwrap();
        let deposit_receipt = executor.receipts[0][1].as_ref().unwrap();

        // deposit_receipt_version is not present in pre canyon transactions
        assert!(deposit_receipt.deposit_receipt_version.is_none());
        assert!(tx_receipt.deposit_receipt_version.is_none());

        // deposit_nonce is present only in deposit transactions
        assert!(deposit_receipt.deposit_nonce.is_some());
        assert!(tx_receipt.deposit_nonce.is_none());
    }

    #[test]
    fn op_deposit_fields_post_canyon() {
        // ensure_create2_deployer will fail if timestamp is set to less then 2
        let header = Header {
            timestamp: 2,
            number: 1,
            gas_limit: 1_000_000,
            gas_used: 42_000,
            ..Header::default()
        };

        let mut db = create_op_state_provider();
        let addr = Address::ZERO;
        let account = Account { balance: U256::MAX, ..Account::default() };

        db.insert_account(addr, account, None, HashMap::new());

        let chain_spec =
            Arc::new(ChainSpecBuilder::from(&*BASE_MAINNET).canyon_activated().build());

        let tx = TransactionSigned::from_transaction_and_signature(
            Transaction::Eip1559(TxEip1559 {
                chain_id: chain_spec.chain.id(),
                nonce: 0,
                gas_limit: 21_000,
                to: TransactionKind::Call(addr),
                ..Default::default()
            }),
            Signature::default(),
        );

        let tx_deposit = TransactionSigned::from_transaction_and_signature(
            Transaction::Deposit(reth_primitives::TxDeposit {
                from: addr,
                to: TransactionKind::Call(addr),
                gas_limit: 21_000,
                ..Default::default()
            }),
            Signature::optimism_deposit_tx_signature(),
        );

        let mut executor = create_op_evm_processor(chain_spec, db);

        // attempt to execute an empty block with parent beacon block root, this should not fail
        executor
            .execute(
                &BlockWithSenders {
                    block: Block {
                        header,
                        body: vec![tx, tx_deposit],
                        ommers: vec![],
                        withdrawals: None,
                    },
                    senders: vec![addr, addr],
                },
                U256::ZERO,
            )
            .expect("Executing a block while canyon is active should not fail");

        let tx_receipt = executor.receipts[0][0].as_ref().unwrap();
        let deposit_receipt = executor.receipts[0][1].as_ref().unwrap();

        // deposit_receipt_version is set to 1 for post canyon deposit transactions
        assert_eq!(deposit_receipt.deposit_receipt_version, Some(1));
        assert!(tx_receipt.deposit_receipt_version.is_none());

        // deposit_nonce is present only in deposit transactions
        assert!(deposit_receipt.deposit_nonce.is_some());
        assert!(tx_receipt.deposit_nonce.is_none());
    }
}
