#![allow(deprecated)]

use candid::Principal;
use core::panic;
use cycles_ledger::endpoints::{CmcCreateCanisterArgs, CmcCreateCanisterError, CanisterSettings};
use fake_cmc::{IcpXdrConversionRateResponse, State};
use ic_cdk::{
    api::{
        call::{
            call_with_payment128, msg_cycles_accept128, msg_cycles_available128, RejectionCode,
        },
        management_canister::main::{CanisterIdRecord, CreateCanisterArgument, CanisterSettings as IcCanisterSettings},
    },
    query,
};
use ic_cdk_macros::update;
use std::cell::RefCell;

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

/// Convert cycles_ledger CanisterSettings to IC CDK CanisterSettings
fn to_ic_canister_settings(settings: &CanisterSettings) -> IcCanisterSettings {
    IcCanisterSettings {
        controllers: settings.controllers.clone(),
        compute_allocation: settings.compute_allocation.clone(),
        memory_allocation: settings.memory_allocation.clone(),
        freezing_threshold: settings.freezing_threshold.clone(),
        reserved_cycles_limit: settings.reserved_cycles_limit.clone(),
        log_visibility: None, // Not exposed in our public API
        wasm_memory_limit: None, // Not exposed in our public API
    }
}

fn main() {}

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

    // Use low-level call_with_payment128 to bypass PocketIC management canister routing issues
    // "Canister <id> is already installed" happens because the canister id counter doesn't take into account that a canister with that id
    // was already created using `provisional_create_canister_with_id`. Simply loop to try the next canister id.
    loop {
        let management_canister = Principal::management_canister();
        let create_arg = CreateCanisterArgument {
            settings: arg.settings.as_ref().map(to_ic_canister_settings),
        };

        let result: Result<(CanisterIdRecord,), (RejectionCode, String)> = call_with_payment128(
            management_canister,
            "create_canister",
            (create_arg,),
            cycles,
        )
        .await;

        match result {
            Ok((record,)) => return Ok(record.canister_id),
            Err(error) => {
                if !error.1.contains("canister id already exists") {
                    panic!("create_canister failed: {:?}", error)
                }
            }
        }
    }
}

#[update]
fn fail_next_create_canister_with(error: CmcCreateCanisterError) {
    STATE.with(|s| s.borrow_mut().fail_next_create_canister_with = Some(error))
}

#[query]
fn get_icp_xdr_conversion_rate() -> IcpXdrConversionRateResponse {
    Default::default()
}

#[query]
fn last_create_canister_args() -> CmcCreateCanisterArgs {
    STATE.with(|s| {
        s.borrow()
            .last_create_canister_args
            .clone()
            .expect("No create_canister call recorded")
    })
}

#[test]
fn test_candid_interface_compatibility() {
    use candid_parser::utils::{service_equal, CandidSource};
    use std::path::PathBuf;

    candid::export_service!();
    let exported_interface = __export_service();

    let expected_interface =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("fake-cmc.did");

    println!(
        "Expected interface: {}\n\n",
        CandidSource::File(expected_interface.as_path())
            .load()
            .unwrap()
            .1
            .unwrap()
    );
    println!("Exported interface: {}\n\n", exported_interface);

    service_equal(
        CandidSource::Text(&exported_interface),
        CandidSource::File(expected_interface.as_path()),
    )
    .expect("The fake-cmc interface is not compatible with the fake-cmc.did file");
}
