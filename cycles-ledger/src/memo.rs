use candid::Principal;
use ic_cdk::api::management_canister::provisional::CanisterId;
use icrc_ledger_types::icrc1::transfer::Memo;
use minicbor::{Decode, Encode, Encoder};

#[derive(Decode, Encode, Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendMemo<'a> {
    #[cbor(n(0), with = "minicbor::bytes")]
    pub receiver: &'a [u8],
}

impl<'a> From<&'a CanisterId> for SendMemo<'a> {
    fn from(canister: &'a CanisterId) -> Self {
        Self {
            receiver: canister.as_slice(),
        }
    }
}

pub fn encode_send_memo(target_canister: &Principal) -> Memo {
    let memo = SendMemo::from(target_canister);
    let mut encoder = Encoder::new(Vec::new());
    encoder.encode(memo).expect("Encoding of memo failed");
    encoder.into_writer().into()
}
