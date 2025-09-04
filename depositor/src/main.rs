use cycles_ledger::endpoints::DepositResult;
use depositor::{
    endpoints::{DepositArg, InitArg},
    Config,
};
use ic_cdk::api::call::call_with_payment128;
use ic_cdk_macros::{init, update};
use std::cell::RefCell;

thread_local! {
    static CONFIG: RefCell<Config> = RefCell::new(Config::default());
}

fn with_config<R>(f: impl FnOnce(&Config) -> R) -> R {
    CONFIG.with(|cell| f(&cell.borrow()))
}

fn main() {}

#[init]
fn init(arg: InitArg) {
    CONFIG.with(|cell| {
        *cell.borrow_mut() = Config {
            ledger_id: arg.ledger_id,
        };
    });
}

#[update]
async fn deposit(arg: DepositArg) -> DepositResult {
    let ledger_id = with_config(|config| config.ledger_id);
    let cycles = arg.cycles;
    let arg = cycles_ledger::endpoints::DepositArg {
        to: arg.to,
        memo: arg.memo,
    };
    let (result,): (DepositResult,) = call_with_payment128(ledger_id, "deposit", (arg,), cycles)
        .await
        .expect("Unable to call deposit");
    result
}

#[test]
fn test_candid_interface_compatibility() {
    use candid_parser::utils::{service_equal, CandidSource};
    use std::path::PathBuf;

    candid::export_service!();
    let exported_interface = __export_service();

    let expected_interface =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("depositor.did");

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
    .expect("The despositor interface is not compatible with the depositor.did file");
}
