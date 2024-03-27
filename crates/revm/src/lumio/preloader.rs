use std::{cell::RefCell, collections::HashSet};

use anyhow::Error;
use reth_primitives::Address;
use revm::Database;

#[derive(Default, Debug)]
pub(crate) struct AccountPreloader {
    touched: RefCell<HashSet<Address>>,
}

impl AccountPreloader {
    pub(crate) fn preload<DB>(&self, address: Address, db: &mut DB) -> Result<(), Error>
    where
        DB: Database,
        DB::Error: std::fmt::Display,
    {
        let mut touched = self.touched.borrow_mut();
        if touched.contains(&address) {
            return Ok(());
        }
        db.basic(address).map_err(|err| Error::msg(err.to_string()))?;
        touched.insert(address);
        Ok(())
    }

    pub(crate) fn clear(&self) {
        let mut touched = self.touched.borrow_mut();
        touched.clear();
    }
}
