#![allow(missing_docs)]
use reth_primitives::{Address, B256, U256};
use revm::{
    primitives::{Account, AccountInfo, Bytecode, HashMap},
    Database, DatabaseCommit,
};
use std::mem;

#[allow(missing_docs)]
#[derive(Debug)]
pub struct TransitionState<DB: Database> {
    pub accounts: HashMap<Address, Account>,
    pub contracts: HashMap<B256, Address>,
    pub original_db: DB,
}

#[allow(missing_docs)]
impl<DB: Database + DatabaseCommit> TransitionState<DB> {
    pub fn new(original_db: DB) -> Self {
        Self { accounts: Default::default(), contracts: Default::default(), original_db }
    }

    pub fn finalize(&mut self) {
        let accs: HashMap<Address, Account> = mem::take(&mut self.accounts);
        self.original_db.commit(accs);
        self.contracts.clear();
    }

    pub fn rollback(&mut self) {
        self.accounts.clear();
        self.contracts.clear();
    }
}

impl<DB: Database> DatabaseCommit for TransitionState<DB> {
    fn commit(&mut self, evm_state: HashMap<Address, Account>) {
        for (addr, acc) in evm_state {
            if acc.info.code.is_some() {
                self.contracts.insert(acc.info.code_hash, addr);
            }
            self.accounts.insert(addr, acc);
        }
    }
}

impl<DB: Database> Database for TransitionState<DB> {
    /// The database error type.
    type Error = DB::Error;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        if let Some(addr) = self.accounts.get(&address) {
            Ok(Some(addr.clone().info))
        } else {
            Ok(self.original_db.basic(address)?.clone())
        }
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        if let Some(address) = self.contracts.get(&code_hash) {
            if let Some(account) = self.accounts.get(address) {
                if let Some(code) = account.info.code.clone() {
                    return Ok(code);
                }
            }
        }
        self.original_db.code_by_hash(code_hash)
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        if let Some(acc_entry) = self.accounts.get(&address) {
            if let Some(slot) = acc_entry.storage.get(&index) {
                Ok(slot.present_value)
            } else {
                Ok(self.original_db.storage(address, index)?)
            }
        } else {
            // Acc needs to be loaded for us to access slots.
            if let Some(_info) = self.original_db.basic(address)? {
                Ok(self.original_db.storage(address, index)?)
            } else {
                Ok(U256::ZERO)
            }
        }
    }

    fn block_hash(&mut self, number: U256) -> Result<B256, Self::Error> {
        self.original_db.block_hash(number)
    }
}
