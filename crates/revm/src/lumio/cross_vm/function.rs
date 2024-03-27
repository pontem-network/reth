use std::mem;

use ethabi::{ethereum_types::U256, ParamType, Token};
use move_binary_format::{
    access::ModuleAccess as _,
    file_format::{Signature, SignatureToken},
    CompiledModule,
};
use move_core_types::{
    account_address::AccountAddress, language_storage::TypeTag, u256::U256 as MoveU256,
    value::MoveValue,
};
use reth_interfaces::executor::BlockExecutionError;

use super::CrossEthEvent;

/// Prepare move call arguments
pub fn prepare_move_args(
    module: &CompiledModule,
    cross_call: &CrossEthEvent,
    sender: AccountAddress,
) -> Result<Vec<Vec<u8>>, BlockExecutionError> {
    let fun = module
        .function_defs
        .iter()
        .find(|def| {
            let identifier_index = module.function_handle_at(def.function).name;
            module.identifier_at(identifier_index) == cross_call.function_name.as_ident_str()
        })
        .ok_or_else(|| BlockExecutionError::CanonicalRevert {
            inner: "[CrossVM]: non-entry function call".into(),
        })?;

    if !fun.is_entry {
        return Err(BlockExecutionError::CanonicalRevert {
            inner: "[CrossVM]: non-entry function call".into(),
        });
    }
    let signature = module.signature_at(module.function_handle_at(fun.function).parameters);
    let params = map_signature(signature, &cross_call.generics)?;
    let mut params = ethabi::decode(dbg!(&params), dbg!(&cross_call.call_data)).map_err(|e| {
        BlockExecutionError::CanonicalRevert {
            inner: format!("[CrossVM]: failed to decode call data {:?}", e),
        }
    })?;

    let mut args = Vec::with_capacity(signature.0.len());
    let mut param_idx = 0;
    for param in signature.0.iter() {
        let value = if param.is_signer() || param.is_signer_ref() {
            MoveValue::Signer(sender)
        } else {
            let val = map_token(&mut params[param_idx], param, &cross_call.generics)?;
            param_idx += 1;
            val
        };
        args.push(bcs::to_bytes(&value).map_err(|e| BlockExecutionError::CanonicalRevert {
            inner: format!("[CrossVM]: failed to encode move value {}", e),
        })?);
    }

    Ok(args)
}

fn map_token(
    tkn: &mut Token,
    sig_token: &SignatureToken,
    tags: &[TypeTag],
) -> Result<MoveValue, BlockExecutionError> {
    Ok(match tkn {
        Token::Address(_) |
        Token::FixedBytes(_) |
        Token::Int(_) |
        Token::String(_) |
        Token::FixedArray(_) |
        Token::Tuple(_) |
        Token::Array(_) => {
            return Err(BlockExecutionError::CanonicalRevert {
                inner: "[CrossVM]: type is not supported".to_string(),
            })
        }
        Token::Bytes(val) => MoveValue::vector_u8(mem::take(val)),
        Token::Bool(val) => MoveValue::Bool(*val),
        Token::Uint(val) => match sig_token {
            SignatureToken::U8 => u256_to_move_u8(*val)?,
            SignatureToken::U64 => u256_to_move_u64(*val)?,
            SignatureToken::U128 => u256_to_move_u128(*val)?,
            SignatureToken::Address => u256_to_move_address(*val)?,
            SignatureToken::U16 => u256_to_move_u16(*val)?,
            SignatureToken::U32 => u256_to_move_u32(*val)?,
            SignatureToken::U256 => u256_to_move_u256(*val)?,
            SignatureToken::TypeParameter(idx) => {
                if let Some(tkn) = tags.get(*idx as usize) {
                    match tkn {
                        TypeTag::U8 => u256_to_move_u8(*val)?,
                        TypeTag::U64 => u256_to_move_u64(*val)?,
                        TypeTag::U128 => u256_to_move_u128(*val)?,
                        TypeTag::Address => u256_to_move_address(*val)?,
                        TypeTag::U16 => u256_to_move_u16(*val)?,
                        TypeTag::U32 => u256_to_move_u32(*val)?,
                        TypeTag::U256 => u256_to_move_u256(*val)?,
                        _ => {
                            return Err(BlockExecutionError::CanonicalRevert {
                                inner: "[CrossVM]: type parameter is not supported".to_string(),
                            })
                        }
                    }
                } else {
                    return Err(BlockExecutionError::CanonicalRevert {
                        inner: "[CrossVM]: type parameter is not provided".to_string(),
                    });
                }
            }
            _ => {
                return Err(BlockExecutionError::CanonicalRevert {
                    inner: "[CrossVM]: uint type is not supported".to_string(),
                })
            }
        },
    })
}

fn map_signature(
    sign: &Signature,
    type_args: &[TypeTag],
) -> Result<Vec<ParamType>, BlockExecutionError> {
    let tokens = sign.0.as_slice();
    if tokens.is_empty() {
        return Ok(vec![]);
    }

    let mut params = Vec::with_capacity(tokens.len());
    let mut signers = 0;
    for param in tokens {
        if let Some(param) = map_signature_token(param, type_args)? {
            params.push(param);
        } else {
            signers += 1;
            if signers > 1 {
                return Err(BlockExecutionError::CanonicalRevert {
                    inner: "[CrossVM]: multiple signers are not supported".to_string(),
                });
            }
        }
    }

    Ok(params)
}

fn map_signature_token(
    tkn: &SignatureToken,
    type_args: &[TypeTag],
) -> Result<Option<ParamType>, BlockExecutionError> {
    Ok(Some(match tkn {
        SignatureToken::Bool => ParamType::Bool,
        SignatureToken::U8 => ParamType::Uint(8),
        SignatureToken::U16 => ParamType::Uint(16),
        SignatureToken::U32 => ParamType::Uint(32),
        SignatureToken::U64 => ParamType::Uint(64),
        SignatureToken::U128 => ParamType::Uint(128),
        SignatureToken::U256 => ParamType::Uint(256),
        SignatureToken::Address => ParamType::Uint(256),
        SignatureToken::Signer => return Ok(None),
        SignatureToken::Reference(tkn) => {
            if tkn.is_signer() {
                return Ok(None);
            } else {
                return Err(BlockExecutionError::CanonicalRevert {
                    inner: "[CrossVM]: references are not supported".to_string(),
                });
            }
        }
        SignatureToken::Vector(tkn) => {
            if let Some(inner) = map_signature_token(tkn, type_args)? {
                if inner == ParamType::Uint(8) {
                    ParamType::Bytes
                } else {
                    ParamType::Array(Box::new(inner))
                }
            } else {
                return Err(BlockExecutionError::CanonicalRevert {
                    inner: "[CrossVM]: vector of signer is not supported".to_string(),
                });
            }
        }
        SignatureToken::Struct(_) => {
            return Err(BlockExecutionError::CanonicalRevert {
                inner: "[CrossVM]: structs are not supported".to_string(),
            })
        }
        SignatureToken::StructInstantiation(_, _) => {
            return Err(BlockExecutionError::CanonicalRevert {
                inner: "[CrossVM]: struct instantiations are not supported".to_string(),
            })
        }
        SignatureToken::MutableReference(_) => {
            return Err(BlockExecutionError::CanonicalRevert {
                inner: "[CrossVM]: mutable references are not supported".to_string(),
            })
        }
        SignatureToken::TypeParameter(idx) => {
            if let Some(tkn) = type_args.get(*idx as usize) {
                map_type_tag(tkn)?
            } else {
                return Err(BlockExecutionError::CanonicalRevert {
                    inner: "[CrossVM]: type parameter is not provided".to_string(),
                });
            }
        }
    }))
}

fn map_type_tag(tkn: &TypeTag) -> Result<ParamType, BlockExecutionError> {
    Ok(match tkn {
        TypeTag::Bool => ParamType::Bool,
        TypeTag::U8 => ParamType::Uint(8),
        TypeTag::U64 => ParamType::Uint(64),
        TypeTag::U128 => ParamType::Uint(128),
        TypeTag::Address => ParamType::Uint(256),
        TypeTag::Signer => {
            return Err(BlockExecutionError::CanonicalRevert {
                inner: "[CrossVM]: signer in generic is not supported".to_string(),
            })
        }
        TypeTag::Vector(tp) => {
            if matches!(tp.as_ref(), TypeTag::U8) {
                ParamType::Bytes
            } else {
                ParamType::Array(Box::new(map_type_tag(tp)?))
            }
        }
        TypeTag::Struct(_) => {
            return Err(BlockExecutionError::CanonicalRevert {
                inner: "[CrossVM]: structs in generic are not supported".to_string(),
            })
        }
        TypeTag::U16 => ParamType::Uint(16),
        TypeTag::U32 => ParamType::Uint(32),
        TypeTag::U256 => ParamType::Uint(256),
    })
}

fn u256_to_move_u8(val: U256) -> Result<MoveValue, BlockExecutionError> {
    if val > u8::max_value().into() {
        return Err(BlockExecutionError::CanonicalRevert {
            inner: "[CrossVM]: uint8 overflow".to_string(),
        });
    }
    Ok(MoveValue::U8(val.as_u32() as u8))
}

fn u256_to_move_u16(val: U256) -> Result<MoveValue, BlockExecutionError> {
    if val > u16::max_value().into() {
        return Err(BlockExecutionError::CanonicalRevert {
            inner: "[CrossVM]: uint16 overflow".to_string(),
        });
    }
    Ok(MoveValue::U16(val.as_u32() as u16))
}

fn u256_to_move_u32(val: U256) -> Result<MoveValue, BlockExecutionError> {
    if val > u32::max_value().into() {
        return Err(BlockExecutionError::CanonicalRevert {
            inner: "[CrossVM]: uint32 overflow".to_string(),
        });
    }
    Ok(MoveValue::U32(val.as_u32()))
}

fn u256_to_move_u64(val: U256) -> Result<MoveValue, BlockExecutionError> {
    if val > u64::max_value().into() {
        return Err(BlockExecutionError::CanonicalRevert {
            inner: "[CrossVM]: uint64 overflow".to_string(),
        });
    }
    Ok(MoveValue::U64(val.as_u64()))
}

fn u256_to_move_u128(val: U256) -> Result<MoveValue, BlockExecutionError> {
    if val > u128::max_value().into() {
        return Err(BlockExecutionError::CanonicalRevert {
            inner: "[CrossVM]: uint128 overflow".to_string(),
        });
    }
    Ok(MoveValue::U128(val.as_u128()))
}

fn u256_to_move_u256(val: U256) -> Result<MoveValue, BlockExecutionError> {
    let mut bytes = [0u8; 32];
    val.to_little_endian(&mut bytes);
    Ok(MoveValue::U256(MoveU256::from_le_bytes(&bytes)))
}

fn u256_to_move_address(val: U256) -> Result<MoveValue, BlockExecutionError> {
    let mut bytes = [0u8; 32];
    val.to_big_endian(&mut bytes);
    Ok(MoveValue::Address(AccountAddress::from(bytes)))
}
