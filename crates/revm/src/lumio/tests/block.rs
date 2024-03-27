use crate::lumio::block::block_id;
use move_executor::types::HashValue;

#[test]
fn test_block_id() {
    let block_id = block_id(13, 42);
    assert_eq!(
        block_id,
        HashValue::from_hex("a3eb1811f2a04cb1fa1b19a8875a3c718c8492b2ac349e92a8954367b11425e3")
            .unwrap(),
    );
}
