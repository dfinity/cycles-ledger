use std::{borrow::Cow, ops::Add};

use candid::Nat;
use ciborium::tag::Required;
use ic_stable_structures::{BoundedStorable, Storable};
use num_traits::{CheckedAdd, ToPrimitive};
use serde::{Deserialize, Serialize, Serializer};

/// The tag number for big positive integers.
// See https://www.rfc-editor.org/rfc/rfc8949.html#name-bignums
const BIGNUM_CBOR_TAG: u64 = 2;

type TaggedRepr = Required<U128Repr, BIGNUM_CBOR_TAG>;

/// The representation of U128 used for serialization.
#[derive(Debug, PartialEq, Eq)]
struct U128Repr(u128);

impl Serialize for U128Repr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0.to_be_bytes())
    }
}

impl<'de> Deserialize<'de> for U128Repr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = U128Repr;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a byte array containing the be bytes of a u128")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() > 16 {
                    return Err(E::custom(format!(
                        "Unable to decode U128 from slice of {} bytes {}",
                        v.len(),
                        hex::encode(v)
                    )));
                }
                // leading zeroes are removed by ciborium
                let mut bytes = [0u8; 16];
                bytes[16 - v.len()..].copy_from_slice(v);
                Ok(U128Repr(u128::from_be_bytes(bytes)))
            }
        }

        deserializer.deserialize_bytes(Visitor)
    }
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct U128(u128);

impl U128 {
    pub const ZERO: Self = Self(0u128);
    pub const ONE: Self = Self(1u128);
    pub const MAX: Self = Self(u128::MAX);

    #[inline]
    pub const fn new(n: u128) -> Self {
        Self(n)
    }

    #[inline]
    pub const fn to_u128(self) -> u128 {
        self.0
    }

    #[inline]
    pub fn try_as_u64(&self) -> Option<u64> {
        self.0.to_u64()
    }
}

impl Add for U128 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.add(rhs.0))
    }
}

impl CheckedAdd for U128 {
    fn checked_add(&self, v: &Self) -> Option<Self> {
        self.0.checked_add(v.0).map(Self)
    }
}

impl std::fmt::Display for U128 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<u64> for U128 {
    fn from(n: u64) -> Self {
        Self(n as u128)
    }
}

impl From<U128> for Nat {
    fn from(u: U128) -> Self {
        use num_bigint::BigUint;
        Self(BigUint::from(u.0))
    }
}

impl From<TaggedRepr> for U128 {
    fn from(Required(U128Repr(n)): TaggedRepr) -> Self {
        Self(n)
    }
}

impl From<U128> for TaggedRepr {
    fn from(U128(n): U128) -> Self {
        Self(U128Repr(n))
    }
}

impl TryFrom<Nat> for U128 {
    type Error = String;

    fn try_from(n: Nat) -> Result<Self, Self::Error> {
        let le_bytes = n.0.to_bytes_le();
        if le_bytes.len() > 16 {
            return Err(format!("amount {} does not fit into u128 token type", n));
        }
        let mut bytes = [0u8; 16];
        bytes[0..le_bytes.len()].copy_from_slice(&le_bytes[..]);
        Ok(Self::new(u128::from_le_bytes(bytes)))
    }
}

impl Storable for U128 {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(self.0.to_be_bytes().to_vec())
    }

    fn from_bytes(bytes: Cow<'_, [u8]>) -> Self {
        assert_eq!(bytes.len(), 16, "u128 representation is 16-bytes long");
        let mut be_bytes = [0u8; 16];
        be_bytes.copy_from_slice(bytes.as_ref());
        Self(u128::from_be_bytes(be_bytes))
    }
}

impl BoundedStorable for U128 {
    const IS_FIXED_SIZE: bool = true;
    const MAX_SIZE: u32 = 32;
}

impl Serialize for U128 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.try_as_u64() {
            Some(n) => serializer.serialize_u64(n),
            None => TaggedRepr::from(*self).serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for U128 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct U128Visitor;

        impl<'de> serde::de::Visitor<'de> for U128Visitor {
            type Value = U128;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("an integer between 0 and 2^128")
            }

            // NB. Ciborium tagged values are represented as enums internally.
            fn visit_enum<E>(self, e: E) -> Result<Self::Value, E::Error>
            where
                E: serde::de::EnumAccess<'de>,
            {
                let repr: TaggedRepr =
                    Deserialize::deserialize(serde::de::value::EnumAccessDeserializer::new(e))?;
                Ok(repr.into())
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(U128::from(value))
            }

            // Both [visit_enum] and [visit_u128] are needed because depending
            // on the context Ciborium will decode an integer from the bytes
            // automatically.
            fn visit_u128<E>(self, v: u128) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(U128::new(v))
            }
        }

        deserializer.deserialize_any(U128Visitor)
    }
}

#[cfg(test)]
mod tests {
    use proptest::{prelude::any, prop_assert_eq, proptest};

    use crate::u128::{U128Repr, U128};

    #[test]
    #[allow(non_snake_case)]
    fn test_U128_roundtrip() {
        let test_conf = proptest::test_runner::Config {
            cases: 2048,
            // Fail as soon as one test fails
            max_local_rejects: 1,
            max_shrink_iters: 0,
            ..Default::default()
        };
        proptest!(test_conf, |(n in any::<u128>())| {
            // U128Repr
            let repr = U128Repr(n);
            let mut bytes = vec![];
            ciborium::ser::into_writer(&repr, &mut bytes).unwrap();
            let actual: U128Repr = ciborium::de::from_reader(&bytes[..]).unwrap();
            prop_assert_eq!(repr, actual);

            // U128
            let n = U128::new(n);
            let mut bytes = vec![];
            ciborium::ser::into_writer(&n, &mut bytes).unwrap();
            println!("{}", hex::encode(&bytes));
            let actual: U128 = ciborium::de::from_reader(&bytes[..]).unwrap();
            prop_assert_eq!(n, actual);
        })
    }
}
