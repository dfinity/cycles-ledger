use candid::Principal;
use core::panic;
use cycles_ledger::endpoints::{CmcCreateCanisterArgs, CmcCreateCanisterError};
use fake_cmc::{IcpXdrConversionRateResponse, State};
use ic_cdk::{
    api::{canister_version, msg_cycles_accept, msg_cycles_available},
    call::Call,
    management_canister::CreateCanisterResult,
    query,
};
use ic_cdk_macros::update;
use std::cell::RefCell;

#[derive(candid::CandidType, candid::Deserialize)]
struct CreateCanisterArgsComplete {
    settings: Option<ic_cdk::management_canister::CanisterSettings>,
    sender_canister_version: Option<u64>,
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

fn main() {}

#[update]
async fn create_canister(arg: CmcCreateCanisterArgs) -> Result<Principal, CmcCreateCanisterError> {
    let cycles = msg_cycles_available();
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
                msg_cycles_accept(cycles - refund_amount);
            }
            CmcCreateCanisterError::RefundFailed { .. } => {
                let _ = msg_cycles_accept(cycles);
            }
        };
        return Err(error);
    };
    msg_cycles_accept(cycles);

    // "Canister <id> is already installed" happens because the canister id counter doesn't take into account that a canister with that id
    // was already created using `provisional_create_canister_with_id`. Simply loop to try the next canister id.
    loop {
        let complete_arg = CreateCanisterArgsComplete {
            settings: arg.settings.clone(),
            sender_canister_version: Some(canister_version()),
        };

        match Call::unbounded_wait(Principal::management_canister(), "create_canister")
            .with_arg(&complete_arg)
            .with_cycles(cycles)
            .await
        {
            Ok(result) => {
                let record: CreateCanisterResult = result
                    .candid()
                    .expect("Failed to decode create_canister result");
                return Ok(record.canister_id);
            }
            Err(error) => {
                ic_cdk::api::debug_print(error.to_string());
                if !error.to_string().contains("canister id already exists") {
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
