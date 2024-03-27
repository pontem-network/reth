use super::{
    CrossVmCall, EthCallEventData, CROSS_VM_ETH_ADDR, CROSS_VM_ETH_TOPIC, CROSS_VM_MV_ADDR,
    CROSS_VM_MV_TOPIC,
};
use crate::{
    lumio::{executor::MoveExecutor, mapper::map_account_address},
    primitives::{
        Env, ExecutionResult, HandlerCfg, OptimismFields, ResultAndState, SpecId, TransactTo, TxEnv,
    },
};
use alloy_primitives::{Address, Bytes};
use aptos_types::contract_event::ContractEvent;
use move_core_types::account_address::AccountAddress;
use reth_interfaces::executor::{BlockExecutionError, MagicBlockExecutionError::CrossVMCallFail};
use reth_primitives::U256;
use revm::{Database, DatabaseCommit, Evm, EvmBuilder};
use std::{collections::VecDeque, fmt::Display};

struct CrossVMRuntime {
    queue: VecDeque<CrossVmCall>,
    available_gas: u64,
    signer: AccountAddress,
}

impl CrossVMRuntime {
    fn new(execution_result: &ExecutionResult, gas: u64, signer: AccountAddress) -> Self {
        let mut runtime = Self { queue: VecDeque::new(), available_gas: gas, signer };
        runtime.fill_queue(execution_result);
        runtime
    }

    fn fill_queue(&mut self, execution_result: &ExecutionResult) {
        if let ExecutionResult::Success { logs, .. } = execution_result {
            for log in logs {
                if log.address == *CROSS_VM_ETH_ADDR &&
                    log.topics().contains(&(*CROSS_VM_ETH_TOPIC))
                {
                    self.queue.push_back(CrossVmCall::Move(log.data.data.clone()))
                } else if log.address == *CROSS_VM_MV_ADDR &&
                    log.topics().contains(&(*CROSS_VM_MV_TOPIC))
                {
                    let contract_event: ContractEvent =
                        bcs::from_bytes(&log.data.data).expect("Can't decode move event");
                    let event_data = contract_event.into_event_data();
                    let event: EthCallEventData =
                        bcs::from_bytes(&event_data).expect("Can't decode EthCallEventData event");
                    self.queue.push_back(CrossVmCall::Eth(event));
                }
            }
        }
    }

    fn run<I, T>(
        &mut self,
        evm: &mut Evm<'_, I, T>,
        mvm: &mut MoveExecutor,
    ) -> Result<(), BlockExecutionError>
    where
        T: Database + DatabaseCommit,
        T::Error: Display,
    {
        while let Some(call) = self.queue.pop_front() {
            let ResultAndState { result, state } = match call {
                CrossVmCall::Move(params) => {
                    let (res_and_state, _) = dbg!(mvm.cross_vm_call(
                        params.as_ref(),
                        self.available_gas,
                        self.signer,
                        &mut evm.context.evm.db,
                    ))?;

                    res_and_state
                }
                CrossVmCall::Eth(event_data) => dbg!(self.exec_eth_call(evm, event_data))?,
            };

            // TODO: fix gas here
            self.available_gas = self.available_gas.saturating_sub(result.gas_used());
            evm.context.evm.db.commit(state);
            self.fill_queue(&result);
        }
        Ok(())
    }

    fn exec_eth_call<T, I>(
        &self,
        evm: &mut Evm<'_, I, T>,
        event_data: EthCallEventData,
    ) -> Result<ResultAndState, BlockExecutionError>
    where
        T: Database,
        T::Error: Display,
    {
        let signer = map_account_address(event_data.move_address);
        let to = if event_data.eth_address.len() == 20 {
            Address::from_slice(&event_data.eth_address)
        } else {
            return Err(cross_vm_error());
        };

        let optimism_fields = OptimismFields {
            source_hash: None,
            mint: None,
            is_system_transaction: Some(false),
            enveloped_tx: Some(Bytes::new()),
        };
        let tx = TxEnv {
            caller: signer,
            gas_limit: self.available_gas,
            gas_price: evm.context.evm.env.tx.gas_price,
            transact_to: TransactTo::Call(to),
            value: U256::ZERO,
            data: Bytes::from(event_data.eth_calldata),
            nonce: None,
            chain_id: None,
            access_list: vec![],
            gas_priority_fee: None,
            blob_hashes: vec![],
            max_fee_per_blob_gas: None,
            optimism: optimism_fields,
        };

        let mut evm = EvmBuilder::default()
            .with_db(&mut evm.context.evm.db)
            .with_handler_cfg(HandlerCfg { spec_id: SpecId::LATEST, is_optimism: true })
            .build();

        evm.context.evm.env = Box::new(Env {
            cfg: evm.context.evm.env.cfg.clone(),
            block: evm.context.evm.env.block.clone(),
            tx,
        });
        evm.transact().map_err(|_| cross_vm_error())
    }
}

/// Run all cross-vm calls, which are stored in the logs of result.
/// Also returns the amount of gas left after all calls.
pub fn run_cross_calls<T, I>(
    tx_result: &ExecutionResult,
    evm: &mut Evm<'_, I, T>,
    mvm: &mut MoveExecutor,
    available_gas: u64,
    signer: AccountAddress,
) -> Result<u64, BlockExecutionError>
where
    T: Database + DatabaseCommit,
    T::Error: Display,
{
    let mut cross_vm_runtime = CrossVMRuntime::new(tx_result, available_gas, signer);

    cross_vm_runtime.run(evm, mvm)?;
    Ok(cross_vm_runtime.available_gas)
}

fn cross_vm_error() -> BlockExecutionError {
    BlockExecutionError::MagicBlockExecution(CrossVMCallFail)
}
