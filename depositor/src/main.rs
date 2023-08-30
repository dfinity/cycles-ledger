use candid::candid_method;
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
#[candid_method(init)]
fn init(arg: InitArg) {
    CONFIG.with(|cell| {
        *cell.borrow_mut() = Config {
            ledger_id: arg.ledger_id,
        };
    });
}

#[update]
#[candid_method]
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
