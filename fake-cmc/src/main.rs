use candid::{candid_method, Principal};
use core::panic;
use cycles_ledger::endpoints::{CmcCreateCanisterArgs, CmcCreateCanisterError};
use fake_cmc::State;
use ic_cdk::{
    api::{
        call::{msg_cycles_accept128, msg_cycles_available128},
        management_canister::main::CreateCanisterArgument,
    },
    query,
};
use ic_cdk_macros::update;
use std::cell::RefCell;

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

fn main() {}

#[candid_method]
#[update]
async fn create_canister(arg: CmcCreateCanisterArgs) -> Result<Principal, CmcCreateCanisterError> {
    let cycles = msg_cycles_available128();
    if cycles < 100_000_000_000 {
        return Err(CmcCreateCanisterError::Refunded {
            refund_amount: cycles,
            create_error: "Insufficient cycles attached.".to_string(),
        });
    }

    let next_error = STATE.with(|s| {
        let mut state = s.borrow_mut();
        state.last_create_canister_args = Some(arg.clone());
        state.fail_next_create_canister_with.take()
    });

    if let Some(error) = next_error {
        match error {
            CmcCreateCanisterError::Refunded { refund_amount, .. } => {
                msg_cycles_accept128(cycles - refund_amount);
            }
            CmcCreateCanisterError::RefundFailed { .. } => {
                let _ = msg_cycles_accept128(cycles);
            }
        };
        return Err(error);
    };
    ic_cdk::api::call::msg_cycles_accept128(cycles);

    // "Canister <id> is already installed" happens because the canister id counter doesn't take into account that a canister with that id
    // was already created using `provisional_create_canister_with_id`. Simply retry to try the next canister id.
    loop {
        match ic_cdk::api::management_canister::main::create_canister(
            CreateCanisterArgument {
                settings: arg.settings.clone(),
            },
            cycles,
        )
        .await
        {
            Ok((record,)) => return Ok(record.canister_id),
            Err(error) => {
                if !error.1.contains("is already installed") {
                    panic!("create_canister failed: {:?}", error)
                }
            }
        }
    }
}

#[candid_method]
#[update]
fn fail_next_create_canister_with(error: CmcCreateCanisterError) {
    STATE.with(|s| s.borrow_mut().fail_next_create_canister_with = Some(error))
}

#[candid_method]
#[query]
fn last_create_canister_args() -> CmcCreateCanisterArgs {
    STATE.with(|s| {
        s.borrow()
            .last_create_canister_args
            .clone()
            .expect("No create_canister call recorded")
    })
}
