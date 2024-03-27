use reth_interfaces::RethResult;

/// Lumio provider trait.
#[auto_impl::auto_impl(&, Arc)]
pub trait LumioProvider: Send + Sync {
    /// Get the block info for the given block number.
    fn get_block_info(&self, number: u64) -> RethResult<Option<Vec<u8>>>;
}
