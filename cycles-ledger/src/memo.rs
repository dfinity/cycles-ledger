use ic_cdk::api::management_canister::provisional::CanisterId;
use minicbor::{Decode, Encode};

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
