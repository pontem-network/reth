use move_executor::types::HashValue;

/// Create a block id from a timestamp and block number.
pub fn block_id(ts: u64, block: u64) -> HashValue {
    HashValue::keccak256_of(&[ts.to_be_bytes(), block.to_be_bytes()].concat())
}
