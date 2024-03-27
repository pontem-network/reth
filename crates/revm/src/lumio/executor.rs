use std::{fmt::Display, sync::Arc};

use crate::primitives::{HaltReason, SuccessReason};
use anyhow::Error;
use move_core_types::{
    ident_str,
    language_storage::{ModuleId, StructTag, TypeTag},
    resolver::MoveResolver,
    value::{serialize_values, MoveValue},
    vm_status::{StatusCode, VMStatus},
};
use move_executor::{
    adapter_common::{preprocess_transaction, VMAdapter},
    data_cache::AsMoveResolver,
    framework,
    gas_schedule::{MiscGasParameters, NativeGasParameters, LATEST_GAS_FEATURE_VERSION},
    move_vm_ext::{MoveResolverExt, SessionId},
    native::SafeNativeBuilder,
    state_view::{StateViewId, TStateView},
    transaction_metadata::TransactionMetadata,
    types::{
        access_path::AccessPath,
        account_address::AccountAddress,
        block_metadata::BlockMetadata,
        contract_event::{ContractEvent, ReadWriteEvent},
        executable::ModulePath,
        on_chain_config::{Features, TimedFeatures},
        state_store::state_key::StateKey,
        transaction::{
            EntryFunction, ExecutionStatus, SignedTransaction, Transaction as MoveTransaction,
            TransactionOutput, TransactionStatus,
        },
        write_set::WriteOp,
        HashValue,
    },
    vm_types::{output::VMOutput, storage::ChangeSetConfigs},
    AdapterLogSchema, AptosVM,
};
use revm::{
    primitives::{
        Account, Bytecode, ExecutionResult, HashMap, Log, LogData, Output, ResultAndState, State,
        StorageSlot,
    },
    Database,
};
use serde::{Deserialize, Serialize};

use super::{
    block::block_id,
    coin::MasterOfCoin,
    cross_vm::{prepare_move_args, CrossEthEvent},
    epoch::Epoch,
    mapper::{map_access_path_to_address, map_account_address, map_account_address_to_move},
    preloader::AccountPreloader,
    resource::{map_storage_key_to_eth, ResourceIO},
    resource_map::{map_resource_list, ResourceMap},
    state_view::EthStorageAdapter,
    tx_info::TransactionInfo,
    tx_type::{LumioGenesisUpdate, ViewCall},
    value::ValueWithMeta,
    version::VersionHolder,
};
use aptos_gas_meter::{StandardGasAlgebra, StandardGasMeter};
use aptos_memory_usage_tracker::MemoryTrackedGasMeter;
use move_binary_format::CompiledModule;
use move_executor::types::transaction::Transaction;
use reth_interfaces::executor::BlockExecutionError;
use reth_primitives::{Address, Bytes, B256, KECCAK_EMPTY, U256};
use tracing::debug;

type MoveExecResult = Result<(VMStatus, VMOutput, Option<String>), VMStatus>;

/// Move executor.
pub struct MoveExecutor {
    vm: Option<AptosVM>,
    master_of_coin: MasterOfCoin,
    block_id: HashValue,
    should_reconfig: bool,
    preloader: AccountPreloader,
    epoch_holder: Epoch,
    version_holder: VersionHolder,
    has_framework: bool,
}

impl Default for MoveExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl MoveExecutor {
    /// Create new MoveExecutor.
    pub fn new() -> Self {
        let builder = SafeNativeBuilder::new(
            11,
            NativeGasParameters::zeros(),
            MiscGasParameters::zeros(),
            TimedFeatures::enable_all(),
            Features::default(),
        );
        framework::natives::all_natives(AccountAddress::ONE, &builder);
        MoveExecutor {
            vm: None,
            block_id: HashValue::zero(),
            master_of_coin: MasterOfCoin::new(),
            should_reconfig: false,
            preloader: AccountPreloader::default(),
            epoch_holder: Epoch::default(),
            version_holder: VersionHolder::default(),
            has_framework: false,
        }
    }

    /// Get epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch_holder.epoch
    }

    /// Has framework.
    pub fn check_framework<DB>(&mut self, db: &mut DB) -> Result<bool, BlockExecutionError>
    where
        DB: Database,
        DB::Error: Display,
    {
        self.ensure_init(db)?;
        Ok(self.has_framework)
    }

    /// Get chain id.
    pub fn chain_id(&self) -> u32 {
        if let Some(vm) = self.vm.as_ref() {
            vm.chain_id()
        } else {
            0
        }
    }

    fn ensure_init<DB>(&mut self, db: &mut DB) -> Result<(), BlockExecutionError>
    where
        DB: Database,
        DB::Error: Display,
    {
        if self.vm.is_none() || !self.version_holder.is_init() {
            let adapter: EthStorageAdapter<'_, &mut DB> =
                EthStorageAdapter::new(db, &self.master_of_coin, &self.preloader);
            if self.vm.is_none() {
                self.vm = Some(AptosVM::new(&adapter));
                self.has_framework = self.epoch_holder.init_epoch(&adapter)?;
            }
            if !self.version_holder.is_init() {
                self.version_holder.load(&adapter)?;
            }
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn is_configured(&self) -> bool {
        self.vm.is_some()
    }

    fn exec_tx_bypass_visibility<S: MoveResolverExt>(
        &self,
        tx: EntryFunction,
        gas_limit: u64,
        resolver: &S,
    ) -> Result<(VMStatus, VMOutput, Option<String>), VMStatus> {
        let vm = self.vm.as_ref().expect("VM not initialized");
        let mut session = vm.new_session(resolver, SessionId::void());

        let log_context: AdapterLogSchema =
            AdapterLogSchema::new(StateViewId::BlockExecution { block_id: self.block_id }, 0);

        let aptos_vm = &self.vm.as_ref().expect("VM not initialized").0;
        let mut gas_meter =
            MemoryTrackedGasMeter::new(StandardGasMeter::new(StandardGasAlgebra::new(
                vm.0.get_gas_feature_version(),
                aptos_vm.get_gas_parameters(&log_context)?.vm.clone(),
                aptos_vm.get_storage_gas_parameters(&log_context)?.clone(),
                gas_limit,
            )));

        let _ = session
            .execute_function_bypass_visibility(
                tx.module(),
                tx.function(),
                tx.ty_args().to_vec(),
                tx.args().to_vec(),
                &mut gas_meter,
            )
            .map_err(|e| e.into_vm_status())?;

        let change_set = session
            .finish(
                &mut (),
                &ChangeSetConfigs::unlimited_at_gas_feature_version(LATEST_GAS_FEATURE_VERSION),
            )
            .map_err(|e| e.into_vm_status())?;

        let txn_data =
            TransactionMetadata { max_gas_amount: gas_limit.into(), ..Default::default() };

        let fee_statement = AptosVM::fee_statement_from_gas_meter(&txn_data, &gas_meter);
        let output = VMOutput::new(
            change_set,
            fee_statement,
            TransactionStatus::Keep(ExecutionStatus::Success),
        );

        Ok((VMStatus::Executed, output, Some(tx.function().to_string())))
    }

    /// Create move account.
    pub fn create_move_account<DB>(
        &mut self,
        recipient: Address,
        gas_limit: u64,
        mut db: DB,
    ) -> Result<Option<(ResultAndState, TransactionInfo)>, BlockExecutionError>
    where
        DB: Database,
        DB::Error: Display,
    {
        self.ensure_init(&mut db)?;

        let address = map_account_address_to_move(recipient);
        let move_val_address = MoveValue::Address(address);

        // Skip if account already exists
        let sv = EthStorageAdapter::new(&mut db, &self.master_of_coin, &self.preloader);
        let resolver = sv.as_move_resolver();
        let resource = resolver.get_resource(
            &address,
            &StructTag {
                address: AccountAddress::ONE,
                module: ident_str!("account").to_owned(),
                name: ident_str!("Account").to_owned(),
                type_params: vec![],
            },
        );

        if resource
            .map_err(|e| BlockExecutionError::CanonicalRevert { inner: e.to_string() })?
            .is_some()
        {
            return Ok(None);
        }

        // Prepare create account tx
        let entry_func = EntryFunction::new(
            ModuleId::new(AccountAddress::ONE, ident_str!("account").to_owned()),
            ident_str!("create_account").to_owned(),
            vec![],
            serialize_values(&vec![move_val_address]),
        );
        let tx_res = self.exec_tx_bypass_visibility(entry_func, gas_limit, &resolver);
        let evm_res = self.make_evm_result(tx_res, &mut db, None)?;

        Ok(Some(evm_res))
    }

    fn load_module<R>(
        &self,
        id: &ModuleId,
        resolver: &R,
    ) -> Result<Arc<CompiledModule>, BlockExecutionError>
    where
        R: MoveResolverExt,
    {
        self
            .vm
            .as_ref()
            .expect("VM not initialized")
            .load_module(id, resolver)
            .map_err(|e| BlockExecutionError::CanonicalRevert {
                inner: format!("[CrossVM]: failed to load module {}", e),
            })
    }

    /// Execute move transaction on CrossVM eth contract call.
    pub fn cross_vm_call<DB>(
        &mut self,
        evm_log: &[u8],
        gas_limit: u64,
        signer: AccountAddress,
        mut db: DB,
    ) -> Result<(ResultAndState, TransactionInfo), BlockExecutionError>
    where
        DB: Database,
        DB::Error: Display,
    {
        self.ensure_init(&mut db)?;

        let sv = EthStorageAdapter::new(&mut db, &self.master_of_coin, &self.preloader);
        let resolver = sv.as_move_resolver();
        let cross_call = CrossEthEvent::decode(evm_log)?;

        let module = self.load_module(&cross_call.module_id, &resolver)?;
        let args = prepare_move_args(&module, &cross_call, signer)?;

        // Prepare create account tx
        let entry_func = EntryFunction::new(
            cross_call.module_id,
            cross_call.function_name,
            cross_call.generics,
            args,
        );
        let tx_res = self.exec_tx_bypass_visibility(entry_func, gas_limit, &resolver);
        let evm_res = dbg!(self.make_evm_result(dbg!(tx_res), &mut db, None))?;

        Ok(evm_res)
    }

    /// Create new block.
    pub fn new_block<DB>(
        &mut self,
        number: u64,
        timestamp: u64,
        db: DB,
    ) -> Result<(ResultAndState, TransactionInfo), BlockExecutionError>
    where
        DB: Database,
        DB::Error: Display,
    {
        self.block_id = block_id(number, timestamp);
        self.exec_tx(
            BlockMetadata::new(
                self.block_id,
                0, // round
                AccountAddress::ONE,
                vec![],
                vec![],
                timestamp * 1_000_000, // seconds to microseconds
            ),
            db,
        )
    }

    /// Finalize block.
    pub fn finalize(&mut self) {
        if self.should_reconfig {
            self.should_reconfig = false;
            self.vm = None;
            self.preloader.clear();
        }
    }

    /// Execute genesis.
    pub fn execute_genesis<DB>(
        &mut self,
        tx: LumioGenesisUpdate,
        mut db: DB,
    ) -> Result<(ResultAndState, TransactionInfo), BlockExecutionError>
    where
        DB: Database,
        DB::Error: Display,
    {
        self.should_reconfig = true;
        let (mut result, info) = self.exec_tx(tx.payload, &mut db)?;

        for alloc in tx.eth_contracts {
            let mut acc = if let Some(acc) =
                db.basic(alloc.address).map_err(|_| BlockExecutionError::ProviderError)?
            {
                acc.into()
            } else {
                Account::new_not_existing()
            };
            acc.info.code_hash = B256::from(HashValue::keccak256_of(&alloc.contract).bytes());
            acc.info.code = Some(Bytecode::new_raw(Bytes::from(alloc.contract)));

            for (key, value) in alloc.storage {
                acc.storage.insert(U256::from(key), StorageSlot::new_changed(U256::ZERO, value));
            }
            acc.mark_created();
            acc.mark_touch();
            result.state.insert(alloc.address, acc);
        }

        Ok((result, info))
    }

    /// Execute transaction.
    pub fn transact<DB>(
        &mut self,
        tx: SignedTransaction,
        _eth_sender: Address, //todo check eth sender
        db: DB,
    ) -> Result<(ResultAndState, TransactionInfo), BlockExecutionError>
    where
        DB: Database,
        DB::Error: Display,
    {
        self.exec_tx(tx, db)
    }

    fn exec_tx<DB>(
        &mut self,
        tx: impl Into<MoveTransaction>,
        mut db: DB,
    ) -> Result<(ResultAndState, TransactionInfo), BlockExecutionError>
    where
        DB: Database,
        DB::Error: Display,
    {
        self.ensure_init(&mut db)?;
        self.master_of_coin.reset();
        let sv = EthStorageAdapter::new(&mut db, &self.master_of_coin, &self.preloader);
        let vm = self.vm.as_ref().expect("VM not initialized");
        let tx = preprocess_transaction::<AptosVM>(tx.into());
        let log_context =
            AdapterLogSchema::new(StateViewId::BlockExecution { block_id: self.block_id }, 0);
        let tx_result = vm.execute_single_transaction(&tx, &sv.as_move_resolver(), &log_context);

        let tx = if let Some(tx) = tx.into_transaction() {
            Some((tx, self.version_holder.next_version()))
        } else {
            None
        };
        self.check_reconfig_eventx(&tx_result);
        self.make_evm_result(tx_result, &mut db, tx)
    }

    fn check_reconfig_eventx(
        &mut self,
        tx_result: &Result<(VMStatus, VMOutput, Option<String>), VMStatus>,
    ) {
        match tx_result {
            Ok((_, output, _)) => {
                let has_reconfig_event = output
                    .change_set()
                    .events()
                    .iter()
                    .map(|evn| evn.get_event_data())
                    .filter_map(|(key, _, tag, _)| {
                        (key.get_creator_address() == AccountAddress::ONE).then_some(tag)
                    })
                    .filter_map(|tag| if let TypeTag::Struct(tag) = tag { Some(tag) } else { None })
                    .any(|strct| {
                        strct.address == AccountAddress::ONE &&
                            strct.module.as_str() == "reconfiguration" &&
                            strct.name.as_str() == "NewEpochEvent"
                    });
                if has_reconfig_event {
                    self.should_reconfig = true;
                }
            }
            Err(_) => {
                //no-op
            }
        }
    }

    fn make_evm_result<DB>(
        &self,
        result: MoveExecResult,
        db: &mut DB,
        tx: Option<(Transaction, u64)>,
    ) -> Result<(ResultAndState, TransactionInfo), BlockExecutionError>
    where
        DB: Database,
        DB::Error: Display,
    {
        match result {
            Ok((status, output, method)) => {
                // We don't care about gas used, because we charge gas in the same way as move.
                let gas_used = output.gas_used();
                let out_status = output.status().clone();
                if out_status.is_keep() {
                    let (tx, version) =
                        tx.unwrap_or_else(|| (Transaction::StateCheckpoint(HashValue::zero()), 0));
                    let change_set = output.into_change_set();
                    let (ws, events) = change_set.unpack();
                    let mut ws = ws.collect::<Vec<_>>();

                    let state = match self.map_state(&mut ws, db) {
                        Ok(state) => state,
                        Err(err) => {
                            return Err(self.map_common_vm_status(
                                VMStatus::Error {
                                    status_code: StatusCode::FAILED_TO_SERIALIZE_WRITE_SET_CHANGES,
                                    sub_status: None,
                                    message: Some(err.to_string()),
                                },
                                gas_used,
                                method,
                            ))
                        }
                    };
                    let logs = Self::map_events(&events)?;
                    let tx_info =
                        TransactionInfo::new(tx, version, status, events, ws, gas_used, out_status);
                    Ok((
                        ResultAndState {
                            result: ExecutionResult::Success {
                                reason: SuccessReason::Return,
                                gas_used,
                                gas_refunded: 0,
                                logs,
                                output: Output::Call(Bytes::default()),
                            },
                            state,
                        },
                        tx_info,
                    ))
                } else {
                    Err(self.map_common_vm_status(status, gas_used, method))
                }
            }
            Err(err) => Err(self.map_common_vm_status(err, 0, None)),
        }
    }

    fn map_state<DB>(&self, ws: &mut [(StateKey, WriteOp)], db: &mut DB) -> Result<State, Error>
    where
        DB: Database,
        DB::Error: Display,
    {
        let mut state = State::default();
        let mut resource_map = ResourceMap::new();

        for (key, op) in ws {
            if let Some(module_path) = key.module_path() {
                self.map_module_state(module_path, op, &mut state, &mut resource_map, db)?;
            } else {
                self.map_resource_state(key, op, &mut state, &mut resource_map, db)?;
            }
        }

        let (key, mut op) = self.version_holder.make_write_op();
        self.map_resource_state(key, &mut op, &mut state, &mut resource_map, db)?;

        for acc in state.values_mut() {
            if acc.is_empty() && acc.info.balance.is_zero() {
                let fake_code = vec![0x13u8, 0x42u8];
                acc.info.code_hash = B256::from(HashValue::keccak256_of(&fake_code).bytes());
                acc.info.code = Some(Bytecode::new_raw(Bytes::from(fake_code)));
            }
        }

        map_resource_list(resource_map, &mut state, db, &self.preloader)?;

        Ok(state)
    }

    fn load_or_create_account<DB>(&self, address: Address, db: &mut DB) -> Result<Account, Error>
    where
        DB: Database,
        DB::Error: Display,
    {
        Ok(if let Some(acc) = db.basic(address).map_err(|err| Error::msg(err.to_string()))? {
            acc.into()
        } else {
            Account::new_not_existing()
        })
    }

    fn map_module_state<DB>(
        &self,
        module_path: AccessPath,
        op: &mut WriteOp,
        state: &mut HashMap<Address, Account>,
        resource_map: &mut ResourceMap,
        db: &mut DB,
    ) -> Result<(), Error>
    where
        DB: Database,
        DB::Error: Display,
    {
        let value = Self::map_write_op(op)?;
        let addr = map_access_path_to_address(&module_path);
        if let std::collections::hash_map::Entry::Vacant(e) = state.entry(addr) {
            e.insert(self.load_or_create_account(addr, db)?);
        }
        let acc = state.get_mut(&addr).unwrap();
        acc.mark_touch();
        match value {
            None => {
                acc.info.code_hash = KECCAK_EMPTY;
                acc.info.code = None;
                acc.mark_selfdestruct();
                resource_map.remove(
                    module_path.address,
                    &StateKey::access_path(module_path),
                    db,
                    &self.preloader,
                )?;
            }
            Some(value_with_meta) => {
                let value = bcs::to_bytes(&value_with_meta)?;
                Self::restore_write_op(op, value_with_meta);
                acc.info.code_hash = B256::from(HashValue::keccak256_of(&value).bytes());
                acc.info.code = Some(Bytecode::new_raw(Bytes::from(value)));
                resource_map.insert(
                    module_path.address,
                    StateKey::access_path(module_path),
                    db,
                    &self.preloader,
                )?;
            }
        }
        Ok(())
    }

    fn map_resource_state<DB>(
        &self,
        key: &StateKey,
        op: &mut WriteOp,
        state: &mut HashMap<Address, Account>,
        resource_map: &mut ResourceMap,
        db: &mut DB,
    ) -> Result<(), Error>
    where
        DB: Database,
        DB::Error: Display,
    {
        let acc_address = map_storage_key_to_eth(key)?.0;
        if let std::collections::hash_map::Entry::Vacant(e) = state.entry(acc_address) {
            e.insert(self.load_or_create_account(acc_address, db)?);
        }
        let mut io = ResourceIO::new(key, db, &self.preloader)?;
        let acc = state.get_mut(&acc_address).expect("unreachable");
        acc.mark_touch();

        let storage: &mut HashMap<
            reth_primitives::ruint::Uint<256, 4>,
            revm::primitives::StorageSlot,
        > = &mut acc.storage;

        let address = match key.get_address() {
            Some(address) => *address,
            None => return Err(Error::msg("Invalid state key")),
        };
        match Self::map_write_op(op)? {
            None => {
                if self.master_of_coin.is_coin_access(key) {
                    acc.info.balance = U256::ZERO;
                }
                io.delete_value(storage)?;
                resource_map.remove(address, key, db, &self.preloader)
            }
            Some(value) => {
                if self.master_of_coin.is_coin_access(key) {
                    let balance_diff = self.master_of_coin.calculate_coin_diff(acc_address, &value);
                    acc.info.balance = balance_diff.apply(acc.info.balance);
                }
                io.modify_value(&value, storage)?;
                Self::restore_write_op(op, value);
                resource_map.insert(address, key.clone(), db, &self.preloader)
            }
        }
    }

    fn map_write_op(op: &mut WriteOp) -> Result<Option<ValueWithMeta>, Error> {
        Ok(match op {
            WriteOp::Creation(data) => {
                Some(ValueWithMeta { value: core::mem::take(data), metadata: None })
            }
            WriteOp::Modification(data) => {
                Some(ValueWithMeta { value: core::mem::take(data), metadata: None })
            }
            WriteOp::CreationWithMetadata { data, metadata } => Some(ValueWithMeta {
                value: core::mem::take(data),
                metadata: Some(metadata.clone()),
            }),
            WriteOp::ModificationWithMetadata { data, metadata } => Some(ValueWithMeta {
                value: core::mem::take(data),
                metadata: Some(metadata.clone()),
            }),
            WriteOp::Deletion => None,
            WriteOp::DeletionWithMetadata { .. } => None,
        })
    }

    fn restore_write_op(op: &mut WriteOp, value: ValueWithMeta) {
        match op {
            WriteOp::Creation(data) => {
                *data = value.value;
            }
            WriteOp::Modification(data) => {
                *data = value.value;
            }
            WriteOp::CreationWithMetadata { data, metadata: _ } => {
                *data = value.value;
            }
            WriteOp::ModificationWithMetadata { data, metadata: _ } => {
                *data = value.value;
            }
            WriteOp::Deletion => {}
            WriteOp::DeletionWithMetadata { .. } => {}
        }
    }

    fn map_events(events: &[ContractEvent]) -> Result<Vec<Log>, BlockExecutionError> {
        events
            .iter()
            .map(|event| {
                Ok(Log {
                    address: map_account_address(event.key().get_creator_address()),
                    data: LogData::new_unchecked(
                        vec![B256::from(
                            HashValue::keccak256_of(
                                event.type_tag().to_canonical_string().as_bytes(),
                            )
                            .bytes(),
                        )],
                        Bytes::from(bcs::to_bytes(event).map_err(|err| {
                            BlockExecutionError::CanonicalCommit { inner: err.to_string() }
                        })?),
                    ),
                })
            })
            .collect()
    }

    fn map_common_vm_status(
        &self,
        status: VMStatus,
        gas_used: u64,
        method: Option<String>,
    ) -> BlockExecutionError {
        let err = VmErrorOutput { status_code: status, method, gas_used };
        BlockExecutionError::CanonicalCommit { inner: err.to_string() }
    }
}

/// VM error output.
#[derive(Debug)]
pub struct VmErrorOutput {
    status_code: VMStatus,
    method: Option<String>,
    gas_used: u64,
}

impl Display for VmErrorOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(loc) = self.method.as_ref() {
            write!(f, "Status: {}. Gas:{} Loc:{}.", self.status_code, self.gas_used, loc)
        } else {
            write!(f, "Status: {}. Gas:{}", self.status_code, self.gas_used)
        }
    }
}

/// View move resource.
pub fn view_resource<DB>(db: DB, key: StateKey) -> ResultAndState
where
    DB: Database,
    DB::Error: Display,
{
    let master_of_coin = MasterOfCoin::new();
    let preloader = AccountPreloader::default();
    let adapter = EthStorageAdapter::new(db, &master_of_coin, &preloader);
    let result = match adapter.get_state_value(&key) {
        Ok(Some(res)) => ExecutionResult::Success {
            reason: SuccessReason::Stop,
            gas_used: 0,
            gas_refunded: 0,
            logs: vec![],
            output: Output::Call(Bytes::from(res.into_bytes())),
        },
        Err(_) | Ok(None) => {
            ExecutionResult::Halt { reason: HaltReason::OpcodeNotFound, gas_used: 0 }
        }
    };

    ResultAndState { result, state: Default::default() }
}

/// Simulate move function call.
pub fn simulate_tx<DB>(mut db: DB, tx: &SignedTransaction) -> ResultAndState
where
    DB: Database,
    DB::Error: Display,
{
    let master_of_coin = MasterOfCoin::new();
    let preloader = AccountPreloader::default();
    let adapter = EthStorageAdapter::new(&mut db, &master_of_coin, &preloader);

    let (status, output) = AptosVM::simulate_signed_transaction(tx, &adapter);
    let result = bcs::to_bytes(&SimulatorResponse { status, output });
    match result {
        Ok(result) => {
            let result = Bytes::from(result);
            ResultAndState {
                result: ExecutionResult::Success {
                    reason: SuccessReason::Return,
                    gas_used: 0,
                    gas_refunded: 0,
                    logs: vec![],
                    output: Output::Call(result),
                },
                state: State::default(),
            }
        }
        Err(err) => ResultAndState {
            result: ExecutionResult::Revert { gas_used: 0, output: Bytes::from(err.to_string()) },
            state: State::default(),
        },
    }
}

/// Simulator response.
#[derive(Debug, Serialize, Deserialize)]
pub struct SimulatorResponse {
    /// VM status.
    pub status: VMStatus,
    /// VM output.
    pub output: TransactionOutput,
}

/// View move function call.
pub fn view_call<DB>(mut db: DB, view: ViewCall) -> ResultAndState
where
    DB: Database,
    DB::Error: Display,
{
    debug!("executing ViewCall");

    let master_of_coin = MasterOfCoin::new();
    let preloader = AccountPreloader::default();
    let adapter = EthStorageAdapter::new(&mut db, &master_of_coin, &preloader);
    let result = AptosVM::execute_view_function(
        &adapter,
        view.module_id,
        view.func_name,
        view.type_args,
        view.arguments,
        view.gas_budget,
    )
    .and_then(|res| bcs::to_bytes(&res).map_err(Error::new));

    debug!("view function executed on vm");

    let execution_result = match result {
        Ok(output) => ExecutionResult::Success {
            reason: SuccessReason::Return,
            gas_used: 0,
            gas_refunded: 0,
            logs: vec![],
            output: Output::Call(Bytes::from(output)),
        },
        Err(err) => {
            let err = err.to_string();
            ExecutionResult::Revert { gas_used: 0, output: Bytes::from(err.as_bytes().to_vec()) }
        }
    };

    ResultAndState { result: execution_result, state: State::default() }
}

impl std::fmt::Debug for MoveExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MoveExecutor")
            .field("block_id", &self.block_id)
            .field("should_reconfig", &self.should_reconfig)
            .finish()
    }
}
