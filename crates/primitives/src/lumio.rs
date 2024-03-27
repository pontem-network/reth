/// The Lumio block info.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LumioBlockInfo {
    /// The block number.
    pub number: u64,
    /// The block hash.
    pub block_info: Vec<u8>,
}
