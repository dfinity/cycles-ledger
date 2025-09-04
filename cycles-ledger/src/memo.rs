#![allow(deprecated)]

use crate::config::MAX_MEMO_LENGTH;
use candid::Principal;
use ic_cdk::api::management_canister::provisional::CanisterId;
use icrc_ledger_types::icrc1::transfer::Memo;
use minicbor::{Decode, Encode, Encoder};

#[derive(Decode, Encode, Debug, Clone, Copy, PartialEq, Eq)]
pub struct WithdrawMemo<'a> {
    #[cbor(n(0), with = "minicbor::bytes")]
    pub receiver: &'a [u8],
}

impl<'a> From<&'a CanisterId> for WithdrawMemo<'a> {
    fn from(canister: &'a CanisterId) -> Self {
        Self {
            receiver: canister.as_slice(),
        }
    }
}

pub fn encode_withdraw_memo(target_canister: &Principal) -> Memo {
    let memo = WithdrawMemo::from(target_canister);
    let mut encoder = Encoder::new(Vec::new());
    encoder.encode(memo).expect("Encoding of memo failed");
    encoder.into_writer().into()
}

pub fn validate_memo(memo: &Option<Memo>) -> Result<(), String> {
    if let Some(memo) = memo {
        if memo.0.len() as u64 > MAX_MEMO_LENGTH {
            return Err(format!(
                "memo length exceeds the maximum of {} bytes",
                MAX_MEMO_LENGTH
            ));
        }
    }
    Ok(())
}
