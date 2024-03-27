use anyhow::Error;
use core::{cmp::min, ops::Range};
use hex_literal::hex;
use move_core_types::account_address::AccountAddress;
use move_executor::{
    crypto::hash::CryptoHash,
    types::state_store::{state_key::StateKey, state_value::StateValue},
};
use reth_primitives::{Address, B256, U256};
use revm::{
    primitives::{HashMap, StorageSlot},
    Database,
};

const MOVE_1_ADDR: AccountAddress =
    AccountAddress::new(hex!("4c8fca47ee43f2f355f13f5042ed26cbb4f9733dd8f5ce4264d6eb8ab6492cc9"));
const MOVE_2_ADDR: AccountAddress =
    AccountAddress::new(hex!("2c26ece3c223e5a9d872a283fe27e5c930300217bd2ae946c79bdb8cc0011438"));
const MOVE_3_ADDR: AccountAddress =
    AccountAddress::new(hex!("06bb47ed95e4cea09451cb7214abb90d70adea702bec1e4ea3bebdf209b2709c"));
const MOVE_4_ADDR: AccountAddress =
    AccountAddress::new(hex!("d0dd8a87a09211fa2d7022ed93966d7dbd3e34cb6ad94df673fc854565e30ed5"));

use super::{mapper::map_account_address, preloader::AccountPreloader, value::ValueWithMeta};

pub(crate) struct ResourceIO<'state, DB> {
    storage: &'state mut DB,
    address: Address,
    root_hash: U256,
}

impl<'state, DB> ResourceIO<'state, DB>
where
    DB: Database,
    DB::Error: std::fmt::Display,
{
    pub(crate) fn new(
        key: &StateKey,
        db: &'state mut DB,
        preloader: &AccountPreloader,
    ) -> Result<Self, Error> {
        let (address, root_hash) = map_storage_key_to_eth(key)?;
        preloader.preload(address, db)?;
        Ok(Self { storage: db, address, root_hash })
    }

    pub(crate) fn address(&self) -> Address {
        self.address
    }

    fn resource_keys(&mut self) -> Result<KeyValueIter<'_, DB>, Error> {
        KeyValueIter::new(self.address, self.root_hash, self.storage)
    }

    pub(crate) fn read_state_value(&mut self) -> Result<Option<StateValue>, Error> {
        let mut value = vec![];
        for item in self.resource_keys()? {
            let item = item?;
            value.extend_from_slice(item.bytes());
        }
        if value.is_empty() {
            Ok(None)
        } else {
            let value: ValueWithMeta = bcs::from_bytes(&value)?;
            Ok(Some(value.into()))
        }
    }

    pub(crate) fn delete_value(
        &mut self,
        storage: &mut HashMap<U256, StorageSlot>,
    ) -> Result<(), Error> {
        for item in self.resource_keys()? {
            let item = item?;
            let slot = storage.entry(item.key()).or_default();
            slot.present_value = U256::ZERO;
            slot.previous_or_original_value = item.value.into();
        }
        Ok(())
    }

    pub(crate) fn modify_value(
        &mut self,
        new_value: &ValueWithMeta,
        storage: &mut HashMap<U256, StorageSlot>,
    ) -> Result<(), Error> {
        let new_value = bcs::to_bytes(new_value)?;
        let mut new_value_keys = ValueSplitter::new(self.root_hash, new_value.as_slice());
        let mut old_value_keys = self.resource_keys()?;

        loop {
            let new_item = new_value_keys.next();
            let (old_value_key, old_value) = match old_value_keys.next() {
                None => (None, U256::ZERO),
                Some(item) => {
                    let item = item?;
                    (Some(item.key), item.value())
                }
            };

            if let Some((new_value_key, new_value)) = new_item {
                storage.insert(
                    new_value_key,
                    StorageSlot { previous_or_original_value: old_value, present_value: new_value },
                );
            } else if let Some(old_value_key) = old_value_key {
                storage.insert(
                    old_value_key,
                    StorageSlot {
                        previous_or_original_value: old_value,
                        present_value: U256::ZERO,
                    },
                );
            } else {
                break;
            }
        }

        Ok(())
    }
}

pub(crate) fn map_storage_key_to_eth(state_key: &StateKey) -> Result<(Address, U256), Error> {
    let address = match state_key.get_address() {
        Some(address) => *address,
        None => return Err(Error::msg("Invalid state key")),
    };
    let hash = CryptoHash::hash(state_key);
    let address = match address {
        AccountAddress::ONE => MOVE_1_ADDR,
        AccountAddress::TWO => MOVE_2_ADDR,
        AccountAddress::THREE => MOVE_3_ADDR,
        AccountAddress::FOUR => MOVE_4_ADDR,
        _ => address,
    };

    Ok((map_account_address(address), U256::from_limbs(bytemuck::cast(hash.bytes()))))
}

pub(crate) struct KeysIter {
    root_hash: U256,
    resource_size: u32,
    is_root: bool,
    inc: U256,
}

impl KeysIter {
    pub(crate) fn new(root_hash: U256, resource_size: u32) -> Self {
        Self { root_hash, resource_size, is_root: true, inc: U256::from(1) }
    }
}

impl Iterator for KeysIter {
    type Item = (U256, Range<usize>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.resource_size == 0 {
            return None;
        }

        if self.is_root {
            self.is_root = false;
            let size = self.resource_size;
            self.resource_size -= min(self.resource_size, 28); // 32 - 4 (size len in bytes);;
            Some((self.root_hash, 4..min(4 + size, 32) as usize))
        } else {
            self.root_hash = self.root_hash.overflowing_add(self.inc).0;
            if self.root_hash == U256::ZERO {
                self.root_hash = U256::from(1);
            }

            let segment_size = min(self.resource_size, 32);
            self.resource_size -= segment_size;
            Some((self.root_hash, 0..segment_size as usize))
        }
    }
}

pub(crate) struct ValueSplitter<'a> {
    keys_iter: KeysIter,
    values: &'a [u8],
    is_root: bool,
}

impl<'a> ValueSplitter<'a> {
    pub(crate) fn new(root_hash: U256, values: &'a [u8]) -> Self {
        Self { keys_iter: KeysIter::new(root_hash, values.len() as u32), values, is_root: true }
    }
}

impl<'a> Iterator for ValueSplitter<'a> {
    type Item = (U256, U256);

    fn next(&mut self) -> Option<Self::Item> {
        let (key, range) = self.keys_iter.next()?;
        let mut value = [0u8; 32];
        if self.is_root {
            self.is_root = false;
            let value_len = self.values.len() as u32;
            value[0..4].copy_from_slice(&value_len.to_le_bytes());
            value[4..4 + range.len()].copy_from_slice(&self.values[0..range.len()]);
            self.values = &self.values[range.len()..];
            Some((key, U256::from_limbs(bytemuck::cast(value))))
        } else {
            value[0..range.len()].copy_from_slice(&self.values[0..range.len()]);
            self.values = &self.values[range.end..];
            Some((key, U256::from_limbs(bytemuck::cast(value))))
        }
    }
}

pub(crate) struct KeyValueIter<'state, DB>
where
    DB: Database,
    DB::Error: std::fmt::Display,
{
    addr: Address,
    keys_iter: KeysIter,
    db: &'state mut DB,
}

impl<'state, DB> KeyValueIter<'state, DB>
where
    DB: Database,
    DB::Error: std::fmt::Display,
{
    fn new(addr: Address, root_hash: U256, db: &'state mut DB) -> Result<Self, Error> {
        let root_value = db.storage(addr, root_hash).map_err(|err| Error::msg(err.to_string()))?;
        let size = Self::get_state_size(root_value);
        Ok(Self { addr, keys_iter: KeysIter::new(root_hash, size), db })
    }

    fn get_state_size(val: U256) -> u32 {
        let hash_val: [u8; 32] = bytemuck::cast(val.into_limbs());
        let mut encoded_size = [0u8; 4];
        encoded_size.copy_from_slice(&hash_val[0..4]);
        u32::from_le_bytes(encoded_size)
    }
}

impl<'state, DB> Iterator for KeyValueIter<'state, DB>
where
    DB: Database,
    DB::Error: std::fmt::Display,
{
    type Item = Result<StoreItem, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let (key, range) = self.keys_iter.next()?;
        let value = self.db.storage(self.addr, key);
        match value {
            Ok(value) => Some(Ok(StoreItem {
                key,
                value: B256::from(bytemuck::cast::<[u64; 4], [u8; 32]>(value.into_limbs())),
                range,
            })),
            Err(err) => Some(Err(anyhow::Error::msg(err.to_string()))),
        }
    }
}

pub(crate) struct StoreItem {
    key: U256,
    value: B256,
    range: Range<usize>,
}

impl StoreItem {
    fn key(&self) -> U256 {
        self.key
    }

    fn value(&self) -> U256 {
        U256::from_limbs(bytemuck::cast(self.value.0))
    }

    fn bytes(&self) -> &[u8] {
        &self.value.0[self.range.clone()]
    }
}

#[cfg(test)]
mod tests {
    use super::{MOVE_1_ADDR, MOVE_2_ADDR, MOVE_3_ADDR, MOVE_4_ADDR};
    use move_core_types::account_address::AccountAddress;
    use reth_primitives::keccak256;

    #[test]
    fn test_move_core_address() {
        assert_eq!(MOVE_1_ADDR, AccountAddress::new(keccak256("MOVE_0x1".as_bytes()).0));
        assert_eq!(MOVE_2_ADDR, AccountAddress::new(keccak256("MOVE_0x2".as_bytes()).0));
        assert_eq!(MOVE_3_ADDR, AccountAddress::new(keccak256("MOVE_0x3".as_bytes()).0));
        assert_eq!(MOVE_4_ADDR, AccountAddress::new(keccak256("MOVE_0x4".as_bytes()).0));
    }
}
