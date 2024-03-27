use crate::lumio::tx_type::{LumioExtension, MagicTx};
use alloy_rlp::{Decodable, Encodable};
use bytes::BytesMut;
use hex_literal::hex;
use move_core_types::{
    account_address::AccountAddress,
    identifier::Identifier,
    language_storage::ModuleId,
    value::{serialize_values, MoveValue},
};
use move_executor::{
    crypto::ed25519::*,
    types::{
        chain_id::ChainId,
        transaction::{
            authenticator::AuthenticationKey, EntryFunction, RawTransaction, TransactionPayload,
        },
    },
};
use reth_primitives::{
    Bytes, Signature, Transaction, TransactionKind, TransactionSigned, TxLegacy, TxType, B256, U256,
};
use std::str::FromStr;

#[test]
fn test_eth_transaction() {
    let tx_bytes =
    hex!("b901f202f901ee05228459682f008459682f11830209bf8080b90195608060405234801561001057600080fd5b50610175806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c80630c49c36c14610030575b600080fd5b61003861004e565b604051610045919061011d565b60405180910390f35b60606020600052600f6020527f68656c6c6f2073746174656d696e64000000000000000000000000000000000060405260406000f35b600081519050919050565b600082825260208201905092915050565b60005b838110156100be5780820151818401526020810190506100a3565b838111156100cd576000848401525b50505050565b6000601f19601f8301169050919050565b60006100ef82610084565b6100f9818561008f565b93506101098185602086016100a0565b610112816100d3565b840191505092915050565b6000602082019050818103600083015261013781846100e4565b90509291505056fea264697066735822122051449585839a4ea5ac23cae4552ef8a96b64ff59d0668f76bfac3796b2bdbb3664736f6c63430008090033c080a0136ebffaa8fc8b9fda9124de9ccb0b1f64e90fbd44251b4c4ac2501e60b104f9a07eb2999eec6d185ef57e91ed099afb0a926c5b536f0155dd67e537c7476e1471");
    let decoded = TransactionSigned::decode(&mut &tx_bytes[..]).unwrap();
    let tx = MagicTx::from(&decoded);
    assert!(!tx.is_move());
    assert_eq!(tx.gas_limit(), 133567);
    assert_eq!(tx.tx_type(), TxType::Eip1559);
    assert_eq!(
        tx.hash(),
        B256::from_slice(
            hex!("7d82c63a0d24b4622cb8f836fff374f64578693b2dfc3db5f53963ecd063674f").as_slice()
        )
    );
    assert_eq!(tx.payload(), hex!("608060405234801561001057600080fd5b50610175806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c80630c49c36c14610030575b600080fd5b61003861004e565b604051610045919061011d565b60405180910390f35b60606020600052600f6020527f68656c6c6f2073746174656d696e64000000000000000000000000000000000060405260406000f35b600081519050919050565b600082825260208201905092915050565b60005b838110156100be5780820151818401526020810190506100a3565b838111156100cd576000848401525b50505050565b6000601f19601f8301169050919050565b60006100ef82610084565b6100f9818561008f565b93506101098185602086016100a0565b610112816100d3565b840191505092915050565b6000602082019050818103600083015261013781846100e4565b90509291505056fea264697066735822122051449585839a4ea5ac23cae4552ef8a96b64ff59d0668f76bfac3796b2bdbb3664736f6c63430008090033").as_slice());
}

#[test]
fn test_move_transaction() {
    let pr_key = Ed25519PrivateKey::from_bytes_unchecked(&hex!(
        "557ca49c61b03d9367106df3a607c01d48c15e3e83519ece1e1cf5254a166e7d"
    ))
    .unwrap();
    let pkey = Ed25519PublicKey::from(&pr_key);
    let addr = AccountAddress::new(*AuthenticationKey::ed25519(&pkey).derived_address());
    let module_id = ModuleId::new(
        AccountAddress::from_hex_literal("0x1").unwrap(),
        Identifier::new("TestModule").unwrap(),
    );
    let args = serialize_values(&vec![MoveValue::U64(1234)]);
    let function_name = Identifier::new("run").unwrap();
    let payload = TransactionPayload::EntryFunction(EntryFunction::new(
        module_id,
        function_name,
        vec![],
        args,
    ));
    let raw_tx =
        RawTransaction::new(addr, 1, payload, 1_000_000, 100, u64::MAX, ChainId::testnet());
    let tx = raw_tx.sign(&pr_key, pkey).unwrap();
    let signed_tx = tx.into_inner();
    let mut encoded_tx = b"MOVE".to_vec();
    bcs::serialize_into(&mut encoded_tx, &signed_tx).unwrap();

    let transaction = Transaction::Legacy(TxLegacy {
        chain_id: Some(4),
        nonce: 15,
        gas_price: 2200000000,
        gas_limit: 34811,
        to: TransactionKind::Create,
        value: U256::from(1234u64),
        input: Bytes::from(encoded_tx),
    });
    let signature = Signature {
        odd_y_parity: true,
        r: U256::from_str("0x35b7bfeb9ad9ece2cbafaaf8e202e706b4cfaeb233f46198f00b44d4a566a981")
            .unwrap(),
        s: U256::from_str("0x612638fb29427ca33b9a3be2a0a561beecfe0269655be160d35e72d366a6a860")
            .unwrap(),
    };
    let tx = TransactionSigned::from_transaction_and_signature(transaction, signature);
    let mut encoded = BytesMut::new();
    tx.encode(&mut encoded);
    let tx = MagicTx::from(&tx);
    assert!(tx.is_move());
    match tx {
        MagicTx::Move(LumioExtension::Signed(decoded_tx), _) => {
            assert_eq!(decoded_tx, signed_tx);
        }
        _ => panic!("Wrong tx type"),
    }
}
