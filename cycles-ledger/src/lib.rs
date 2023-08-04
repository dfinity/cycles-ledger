use std::collections::BTreeMap;

use ciborium::Value as CiboriumValue;
use icrc_ledger_types::icrc::generic_value::Value;
use serde_bytes::ByteBuf;
use thiserror::Error;

pub mod compact_account;
pub mod config;
pub mod endpoints;
pub mod memo;
pub mod storage;

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
    value: CiboriumValue,
    depth: usize,
) -> Result<Value, ValueDecodingError> {
    if depth >= VALUE_DEPTH_LIMIT {
        return Err(ValueDecodingError::DepthLimitExceeded {
            max_depth: VALUE_DEPTH_LIMIT,
        });
    }

    match value {
        CiboriumValue::Integer(int) => {
            let v: i128 = int.into();
            let uv: u128 = v
                .try_into()
                .map_err(|_| ValueDecodingError::UnsupportedValueType("negative integers"))?;
            Ok(Value::Int(uv.into()))
        }
        CiboriumValue::Bytes(bytes) => Ok(Value::Blob(ByteBuf::from(bytes))),
        CiboriumValue::Text(text) => Ok(Value::Text(text)),
        CiboriumValue::Array(values) => Ok(Value::Array(
            values
                .into_iter()
                .map(|v| ciborium_to_generic_value(v, depth + 1))
                .collect::<Result<Vec<_>, _>>()?,
        )),
        CiboriumValue::Map(map) => Ok(Value::Map(
            map.into_iter()
                .map(|(k, v)| {
                    let key = k
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
            ciborium_to_generic_value(*value, depth + 1)
        }
        CiboriumValue::Tag(known_tags::BIGNUM, value) => {
            let value_bytes = value
                .into_bytes()
                .map_err(|_| ValueDecodingError::UnsupportedValueType("non-bytes bignums"))?;
            Ok(Value::Nat(candid::Nat(num_bigint::BigUint::from_bytes_be(
                &value_bytes,
            ))))
        }
        CiboriumValue::Tag(tag, value) => Err(ValueDecodingError::UnsupportedTag(tag, *value)),
        // NB. ciborium::value::Value is marked as #[non_exhaustive]
        other => Err(ValueDecodingError::UnsupportedValue(other)),
    }
}

mod known_tags {
    //! This module defines well-known CBOR tags used for block decoding.

    /// Tag for Self-described CBOR; see https://www.rfc-editor.org/rfc/rfc8949.html#name-self-described-cbor.
    pub const SELF_DESCRIBED: u64 = 55799;

    /// Tag for CBOR bignums; see https://www.rfc-editor.org/rfc/rfc8949.html#name-bignums.
    pub const BIGNUM: u64 = 2;
}
