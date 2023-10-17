use std::collections::BTreeMap;

use anyhow::{bail, Context};
use ciborium::Value as CiboriumValue;
use icrc_ledger_types::{
    icrc::generic_value::Value, icrc1::transfer::TransferError,
    icrc2::transfer_from::TransferFromError,
};
use num_traits::ToPrimitive;
use serde_bytes::ByteBuf;
use thiserror::Error;

pub mod compact_account;
pub mod config;
pub mod endpoints;
pub mod logs;
pub mod memo;
pub mod storage;
pub mod u128;

/// The maximum allowed value nesting within a CBOR value.
const VALUE_DEPTH_LIMIT: usize = 64;

#[derive(Debug, Error)]
pub enum ValueDecodingError {
    #[error("CBOR value depth must not exceed {max_depth}")]
    DepthLimitExceeded { max_depth: usize },
    #[error("unsupported CBOR map key value {0:?} (only text keys are allowed)")]
    UnsupportedKeyType(String),
    #[error("unsupported CBOR tag {0} (value = {1:?})")]
    UnsupportedTag(u64, CiboriumValue),
    #[error("unsupported CBOR value value {0}")]
    UnsupportedValueType(&'static str),
    #[error("cannot decode CBOR value {0:?}")]
    UnsupportedValue(CiboriumValue),
}

pub fn ciborium_to_generic_value(
    value: &CiboriumValue,
    depth: usize,
) -> Result<Value, ValueDecodingError> {
    if depth >= VALUE_DEPTH_LIMIT {
        return Err(ValueDecodingError::DepthLimitExceeded {
            max_depth: VALUE_DEPTH_LIMIT,
        });
    }

    match value {
        CiboriumValue::Integer(int) => {
            let v: i128 = (*int).into();
            let uv: u128 = v
                .try_into()
                .map_err(|_| ValueDecodingError::UnsupportedValueType("negative integers"))?;
            Ok(Value::Int(uv.into()))
        }
        CiboriumValue::Bytes(bytes) => Ok(Value::Blob(ByteBuf::from(bytes.to_owned()))),
        CiboriumValue::Text(text) => Ok(Value::Text(text.to_owned())),
        CiboriumValue::Array(values) => Ok(Value::Array(
            values
                .iter()
                .map(|v| ciborium_to_generic_value(v, depth + 1))
                .collect::<Result<Vec<_>, _>>()?,
        )),
        CiboriumValue::Map(map) => Ok(Value::Map(
            map.iter()
                .map(|(k, v)| {
                    let key = k
                        .to_owned()
                        .into_text()
                        .map_err(|k| ValueDecodingError::UnsupportedKeyType(format!("{:?}", k)))?;
                    Ok((key, ciborium_to_generic_value(v, depth + 1)?))
                })
                .collect::<Result<BTreeMap<_, _>, _>>()?,
        )),
        CiboriumValue::Bool(_) => Err(ValueDecodingError::UnsupportedValueType("bool")),
        CiboriumValue::Null => Err(ValueDecodingError::UnsupportedValueType("null")),
        CiboriumValue::Float(_) => Err(ValueDecodingError::UnsupportedValueType("float")),
        CiboriumValue::Tag(known_tags::SELF_DESCRIBED, value) => {
            ciborium_to_generic_value(value, depth + 1)
        }
        CiboriumValue::Tag(known_tags::BIGNUM, value) => {
            let value_bytes = value
                .to_owned()
                .into_bytes()
                .map_err(|_| ValueDecodingError::UnsupportedValueType("non-bytes bignums"))?;
            Ok(Value::Nat(candid::Nat(num_bigint::BigUint::from_bytes_be(
                &value_bytes,
            ))))
        }
        CiboriumValue::Tag(tag, value) => {
            Err(ValueDecodingError::UnsupportedTag(*tag, *value.to_owned()))
        }
        // NB. ciborium::value::Value is marked as #[non_exhaustive]
        other => Err(ValueDecodingError::UnsupportedValue(other.to_owned())),
    }
}

pub fn generic_to_ciborium_value(value: &Value, depth: usize) -> anyhow::Result<CiboriumValue> {
    if depth >= VALUE_DEPTH_LIMIT {
        bail!("Depth limit exceeded (max_depth: {})", VALUE_DEPTH_LIMIT);
    }

    match value {
        Value::Int(int) => {
            let uv = int.0.to_u128().context("Unable to convert int to u128")?;
            let v = i128::try_from(uv).context("Unable to convert u128 to i128")?;
            let i = ciborium::value::Integer::try_from(v)
                .context("Unable to create ciborium Integer from i128")?;
            Ok(CiboriumValue::Integer(i))
        }
        Value::Blob(bytes) => Ok(CiboriumValue::Bytes(bytes.to_vec())),
        Value::Text(text) => Ok(CiboriumValue::Text(text.to_owned())),
        Value::Array(values) => Ok(CiboriumValue::Array(
            values
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    generic_to_ciborium_value(v, depth + 1)
                        .with_context(|| format!("Unable to convert element {}", i))
                })
                .collect::<Result<Vec<_>, _>>()?,
        )),
        Value::Map(map) => Ok(CiboriumValue::Map(
            map.iter()
                .map(|(k, v)| {
                    let key = CiboriumValue::Text(k.to_owned());
                    let value = generic_to_ciborium_value(v, depth + 1)
                        .with_context(|| format!("Unable to convert field {}", k))?;
                    Ok::<(CiboriumValue, CiboriumValue), anyhow::Error>((key, value))
                })
                .collect::<Result<Vec<_>, _>>()?,
        )),
        Value::Nat(nat) => {
            let value_bytes = nat.0.to_bytes_be();
            let value = CiboriumValue::try_from(value_bytes)?;
            Ok(CiboriumValue::Tag(known_tags::BIGNUM, Box::new(value)))
        }
        v => bail!("Unknown value: {:?}", v),
    }
}

mod known_tags {
    //! This module defines well-known CBOR tags used for block decoding.

    /// Tag for Self-described CBOR; see https://www.rfc-editor.org/rfc/rfc8949.html#name-self-described-cbor.
    pub const SELF_DESCRIBED: u64 = 55799;

    /// Tag for CBOR bignums; see https://www.rfc-editor.org/rfc/rfc8949.html#name-bignums.
    pub const BIGNUM: u64 = 2;
}

// Traps if the error is InsufficientAllowance
pub fn transfer_from_error_to_transfer_error(e: TransferFromError) -> TransferError {
    match e {
        TransferFromError::BadFee { expected_fee } => TransferError::BadFee { expected_fee },
        TransferFromError::BadBurn { min_burn_amount } => {
            TransferError::BadBurn { min_burn_amount }
        }
        TransferFromError::InsufficientFunds { balance } => {
            TransferError::InsufficientFunds { balance }
        }
        TransferFromError::InsufficientAllowance { .. } => {
            ic_cdk::trap("InsufficientAllowance error should not happen for transfer")
        }
        TransferFromError::TooOld => TransferError::TooOld,
        TransferFromError::CreatedInFuture { ledger_time } => {
            TransferError::CreatedInFuture { ledger_time }
        }
        TransferFromError::Duplicate { duplicate_of } => TransferError::Duplicate { duplicate_of },
        TransferFromError::TemporarilyUnavailable => TransferError::TemporarilyUnavailable,
        TransferFromError::GenericError {
            error_code,
            message,
        } => TransferError::GenericError {
            error_code,
            message,
        },
    }
}

#[cfg(test)]
mod tests {
    use ciborium::{value::Integer, Value};
    use num_bigint::BigUint;
    use proptest::{arbitrary::any, prelude::prop, prop_oneof, proptest, strategy::Strategy};

    use crate::{ciborium_to_generic_value, generic_to_ciborium_value, known_tags};

    fn ciborium_value_strategy() -> impl Strategy<Value = Value> {
        let integer_strategy = any::<u64>().prop_map(|i| Value::Integer(Integer::from(i)));
        let bytes_strategy = any::<Vec<u8>>().prop_map(Value::Bytes);
        let text_strategy = any::<String>().prop_map(Value::Text);
        let bignum_strategy = any::<Vec<u32>>().prop_map(|digits| {
            let value_bytes = BigUint::new(digits).to_bytes_be();
            let value = Value::Bytes(value_bytes);
            Value::Tag(known_tags::BIGNUM, Box::new(value))
        });

        let leaf = prop_oneof![
            integer_strategy,
            bytes_strategy,
            text_strategy.clone(),
            bignum_strategy,
        ];

        leaf.prop_recursive(
            8,   // 8 levels deep
            256, // Shoot for maximum size of 256 nodes
            10,  // We put up to 10 items per collection
            |inner| {
                prop_oneof![
                    // Take the inner strategy and make the two recursive cases.
                    prop::collection::vec(inner.clone(), 0..10).prop_map(Value::Array),
                    // Note that we force the key to be of type text because
                    // it's the only key type supported.
                    // We also use btree_map because we need the keys sorted for when
                    // we check equality.
                    prop::collection::btree_map(any::<String>(), inner, 0..10).prop_map(|kvs| {
                        let kvs = kvs.into_iter().map(|(k, v)| (Value::Text(k), v)).collect();
                        Value::Map(kvs)
                    }),
                ]
            },
        )
    }

    proptest! {
        #[test]
        fn test_ciborium_to_generic_value(value in ciborium_value_strategy()) {
            let ciborium_value = ciborium_to_generic_value(&value, 0)
                .expect("Unable to convert ciborium value to generic value");
            let actual_value = generic_to_ciborium_value(&ciborium_value, 0)
                .expect("Unable to convert generic value to ciborium value");
            assert_eq!(value, actual_value);
        }
    }
}
