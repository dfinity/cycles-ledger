use candid::{candid_method, Nat, Principal};
use cycles_ledger::endpoints::{
    CmcCreateCanisterArgs, DataCertificate, GetArchivesArgs, GetArchivesResult, GetBlocksArgs,
    GetBlocksResult, LedgerArgs, SupportedBlockType, WithdrawError, WithdrawFromError,
};
use cycles_ledger::logs::{Log, LogEntry, Priority};
use cycles_ledger::logs::{P0, P1};
use cycles_ledger::storage::{
    balance_of, mutate_config, mutate_state, prune, read_config, read_state, State,
};
use cycles_ledger::{
    config, create_canister_from_error_to_create_canister_error, endpoints, storage,
    transfer_from_error_to_transfer_error, withdraw_from_error_to_withdraw_error,
};
use ic_canister_log::export as export_logs;
use ic_canisters_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_cdk::api::call::{msg_cycles_accept128, msg_cycles_available128};
use ic_cdk_macros::{init, post_upgrade, query, update};
use icrc_ledger_types::icrc::generic_metadata_value::MetadataValue;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::TransferArg as TransferArgs;
use icrc_ledger_types::icrc1::transfer::{Memo, TransferError};
use icrc_ledger_types::icrc103::get_allowances::{
    Allowances, GetAllowancesArgs, GetAllowancesError,
};
use icrc_ledger_types::icrc2::allowance::{Allowance, AllowanceArgs};
use icrc_ledger_types::icrc2::approve::{ApproveArgs, ApproveError};
use icrc_ledger_types::icrc2::transfer_from::{TransferFromArgs, TransferFromError};
use num_traits::ToPrimitive;

#[init]
#[candid_method(init)]
fn init(ledger_args: LedgerArgs) {
    match ledger_args {
        LedgerArgs::Init(config) => {
            mutate_state(|state| {
                state.config.set(config)
                    .expect("Failed to change configuration");
            })
        }
        LedgerArgs::Upgrade(_) =>
            ic_cdk::trap("Cannot initialize the canister with an Upgrade argument. Please provide an Init argument."),
    }
}

#[post_upgrade]
fn post_upgrade(ledger_args: Option<LedgerArgs>) {
    match ledger_args {
        Some(LedgerArgs::Upgrade(Some(upgrade_args))) => {
            if let Some(max_blocks_per_request) = upgrade_args.max_blocks_per_request {
                mutate_config(|config| {
                    config.max_blocks_per_request = max_blocks_per_request;
                })
            }
            if let Some(change_index_id) = upgrade_args.change_index_id {
                mutate_config(|config| {
                    config.index_id = change_index_id.into();
                })
            }
        }
        None | Some(LedgerArgs::Upgrade(None)) => {},
        _ =>
            ic_cdk::trap("Cannot upgrade the canister with an Init argument. Please provide an Upgrade argument."),
    }
}

#[query]
#[candid_method(query)]
fn icrc1_name() -> String {
    config::TOKEN_NAME.to_string()
}

#[query]
#[candid_method(query)]
fn icrc1_symbol() -> String {
    config::TOKEN_SYMBOL.to_string()
}

#[query]
#[candid_method(query)]
fn icrc1_decimals() -> u8 {
    config::DECIMALS
}

#[query]
#[candid_method(query)]
fn icrc1_fee() -> Nat {
    Nat::from(config::FEE)
}

#[query]
#[candid_method(query)]
fn icrc1_minting_account() -> Option<Account> {
    None
}

#[query]
#[candid_method(query)]
fn icrc1_supported_standards() -> Vec<endpoints::SupportedStandard> {
    vec![
        endpoints::SupportedStandard {
            name: "ICRC-1".to_string(),
            url: "https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-1/README.md"
                .to_string(),
        },
        endpoints::SupportedStandard {
            name: "ICRC-2".to_string(),
            url: "https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-2/README.md"
                .to_string(),
        },
        endpoints::SupportedStandard {
            name: "ICRC-3".to_string(),
            url: "https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-3/README.md"
                .to_string(),
        },
    ]
}

#[query]
#[candid_method(query)]
fn icrc3_supported_block_types() -> Vec<SupportedBlockType> {
    vec![
        SupportedBlockType {
            block_type: "1burn".to_string(),
            url: "https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-1/README.md"
                .to_string(),
        },
        SupportedBlockType {
            block_type: "1mint".to_string(),
            url: "https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-1/README.md"
                .to_string(),
        },
        SupportedBlockType {
            block_type: "2xfer".to_string(),
            url: "https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-2/README.md"
                .to_string(),
        },
        SupportedBlockType {
            block_type: "2approve".to_string(),
            url: "https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-2/README.md"
                .to_string(),
        },
    ]
}

#[query]
#[candid_method(query)]
fn icrc1_total_supply() -> Nat {
    Nat::from(read_state(|state| state.total_supply()))
}

#[query]
#[candid_method(query)]
fn icrc1_metadata() -> Vec<(String, MetadataValue)> {
    use MetadataValue as MV;

    let mut metadata = vec![
        MV::entry("icrc1:decimals", config::DECIMALS as u64),
        MV::entry("icrc1:name", config::TOKEN_NAME),
        MV::entry("icrc1:symbol", config::TOKEN_SYMBOL),
        MV::entry("icrc1:fee", config::FEE),
        MV::entry("icrc1:max_memo_length", config::MAX_MEMO_LENGTH),
        MV::entry(
            "dfn:max_blocks_per_request",
            read_config(|config| config.max_blocks_per_request),
        ),
        MV::entry("icrc1:logo", config::TOKEN_LOGO),
    ];
    if let Some(index_id) = read_config(|config| config.index_id) {
        metadata.push(MV::entry("dfn:index_id", index_id.as_slice()))
    }
    metadata
}

#[query]
#[candid_method(query)]
fn icrc1_balance_of(account: Account) -> Nat {
    Nat::from(storage::balance_of(&account))
}

#[update]
#[candid_method]
fn deposit(arg: endpoints::DepositArg) -> endpoints::DepositResult {
    let cycles_available = msg_cycles_available128();
    let amount = msg_cycles_accept128(cycles_available);

    match storage::deposit(arg.to, amount, arg.memo, ic_cdk::api::time()) {
        Ok(res) => res,
        Err(err) => ic_cdk::trap(&err.to_string()),
    }
}

fn execute_transfer(
    from: Account,
    to: Account,
    spender: Option<Account>,
    amount: Nat,
    fee: Option<Nat>,
    memo: Option<Memo>,
    created_at_time: Option<u64>,
) -> Result<Nat, TransferFromError> {
    let Some(amount) = amount.0.to_u128() else {
        return Err(TransferFromError::InsufficientFunds {
            balance: Nat::from(storage::balance_of(&from)),
        });
    };

    let suggested_fee = match fee {
        Some(fee) => match fee.0.to_u128() {
            None => {
                return Err(TransferFromError::BadFee {
                    expected_fee: Nat::from(config::FEE),
                })
            }
            Some(fee) => Some(fee),
        },
        None => None,
    };

    let now = ic_cdk::api::time();
    let block_index = storage::transfer(
        from,
        to,
        spender,
        amount,
        memo,
        now,
        created_at_time,
        suggested_fee,
    )?;

    prune(now);

    Ok(block_index)
}

#[update]
#[candid_method]
fn icrc1_transfer(args: TransferArgs) -> Result<Nat, TransferError> {
    let from = Account {
        owner: ic_cdk::caller(),
        subaccount: args.from_subaccount,
    };

    execute_transfer(
        from,
        args.to,
        None,
        args.amount,
        args.fee,
        args.memo,
        args.created_at_time,
    )
    .map_err(transfer_from_error_to_transfer_error)
}

#[update]
#[candid_method]
fn icrc2_transfer_from(args: TransferFromArgs) -> Result<Nat, TransferFromError> {
    let spender = Account {
        owner: ic_cdk::caller(),
        subaccount: args.spender_subaccount,
    };
    execute_transfer(
        args.from,
        args.to,
        Some(spender),
        args.amount,
        args.fee,
        args.memo,
        args.created_at_time,
    )
}

#[query]
#[candid_method(query)]
fn icrc3_get_blocks(args: GetBlocksArgs) -> GetBlocksResult {
    storage::get_blocks(args)
}

async fn execute_withdraw(
    from: Account,
    to: Principal,
    spender: Option<Account>,
    amount: Nat,
    created_at_time: Option<u64>,
) -> Result<Nat, WithdrawFromError> {
    let Some(amount) = amount.0.to_u128() else {
        return Err(WithdrawFromError::InsufficientFunds {
            balance: Nat::from(balance_of(&from)),
        });
    };

    let now = ic_cdk::api::time();
    storage::withdraw(from, to, spender, amount, now, created_at_time).await
}

#[update]
#[candid_method]
async fn withdraw(args: endpoints::WithdrawArgs) -> Result<Nat, WithdrawError> {
    let from = Account {
        owner: ic_cdk::caller(),
        subaccount: args.from_subaccount,
    };
    execute_withdraw(from, args.to, None, args.amount, args.created_at_time)
        .await
        .map_err(withdraw_from_error_to_withdraw_error)
}

#[update]
#[candid_method]
async fn withdraw_from(args: endpoints::WithdrawFromArgs) -> Result<Nat, WithdrawFromError> {
    let spender = Account {
        owner: ic_cdk::caller(),
        subaccount: args.spender_subaccount,
    };
    execute_withdraw(
        args.from,
        args.to,
        Some(spender),
        args.amount,
        args.created_at_time,
    )
    .await
}

async fn execute_create_canister(
    from: Account,
    spender: Option<Account>,
    amount: Nat,
    created_at_time: Option<u64>,
    creation_args: Option<CmcCreateCanisterArgs>,
) -> Result<endpoints::CreateCanisterSuccess, endpoints::CreateCanisterFromError> {
    let Some(amount) = amount.0.to_u128() else {
        return Err(endpoints::CreateCanisterFromError::InsufficientFunds {
            balance: Nat::from(balance_of(&from)),
        });
    };
    let now = ic_cdk::api::time();
    storage::create_canister(from, spender, amount, now, created_at_time, creation_args).await
}

#[update]
#[candid_method]
async fn create_canister(
    args: endpoints::CreateCanisterArgs,
) -> Result<endpoints::CreateCanisterSuccess, endpoints::CreateCanisterError> {
    let from = Account {
        owner: ic_cdk::caller(),
        subaccount: args.from_subaccount,
    };

    execute_create_canister(
        from,
        None,
        args.amount,
        args.created_at_time,
        args.creation_args,
    )
    .await
    .map_err(create_canister_from_error_to_create_canister_error)
}

#[update]
#[candid_method]
async fn create_canister_from(
    args: endpoints::CreateCanisterFromArgs,
) -> Result<endpoints::CreateCanisterSuccess, endpoints::CreateCanisterFromError> {
    let spender = Account {
        owner: ic_cdk::caller(),
        subaccount: args.spender_subaccount,
    };
    execute_create_canister(
        args.from,
        Some(spender),
        args.amount,
        args.created_at_time,
        args.creation_args,
    )
    .await
}

#[query]
#[candid_method(query)]
fn icrc2_allowance(args: AllowanceArgs) -> Allowance {
    let allowance = storage::allowance(&args.account, &args.spender, ic_cdk::api::time());
    let expires_at = if allowance.1 > 0 {
        Some(allowance.1)
    } else {
        None
    };
    Allowance {
        allowance: Nat::from(allowance.0),
        expires_at,
    }
}

#[update]
#[candid_method]
fn icrc2_approve(args: ApproveArgs) -> Result<Nat, ApproveError> {
    let from = Account {
        owner: ic_cdk::api::caller(),
        subaccount: args.from_subaccount,
    };

    let now = ic_cdk::api::time();

    let expected_allowance = match args.expected_allowance {
        Some(n) => match n.0.to_u128() {
            None => {
                return Err(ApproveError::AllowanceChanged {
                    current_allowance: Nat::from(storage::allowance(&from, &args.spender, now).0),
                })
            }
            Some(n) => Some(n),
        },
        None => None,
    };
    let suggested_fee = match args.fee {
        Some(fee) => match fee.0.to_u128() {
            None => {
                return Err(ApproveError::BadFee {
                    expected_fee: Nat::from(config::FEE),
                })
            }
            Some(fee) => Some(fee),
        },
        None => None,
    };

    let block_index = storage::approve(
        from,
        args.spender,
        args.amount.0.to_u128().unwrap_or(u128::MAX),
        args.memo,
        now,
        args.created_at_time,
        suggested_fee,
        expected_allowance,
        args.expires_at,
    )?;

    prune(now);

    Ok(block_index)
}

#[query]
#[candid_method(query)]
fn icrc103_get_allowances(arg: GetAllowancesArgs) -> Result<Allowances, GetAllowancesError> {
    let from_account = match arg.from_account {
        Some(from_account) => from_account,
        None => Account {
            owner: ic_cdk::api::caller(),
            subaccount: None,
        },
    };
    let max_results = arg
        .take
        .map(|take| take.0.to_u64().unwrap_or(config::MAX_TAKE_ALLOWANCES))
        .map(|take| std::cmp::min(take, config::MAX_TAKE_ALLOWANCES))
        .unwrap_or(config::MAX_TAKE_ALLOWANCES);
    Ok(storage::get_allowances(
        from_account,
        arg.prev_spender,
        max_results,
        ic_cdk::api::time(),
    ))
}

#[query]
#[candid_method(query)]
fn http_request(req: HttpRequest) -> HttpResponse {
    if req.path() == "/metrics" {
        let mut writer =
            ic_metrics_encoder::MetricsEncoder::new(vec![], ic_cdk::api::time() as i64 / 1_000_000);

        match encode_metrics(&mut writer) {
            Ok(()) => HttpResponseBuilder::ok()
                .header("Content-Type", "text/plain; version=0.0.4")
                .with_body_and_content_length(writer.into_inner())
                .build(),
            Err(err) => {
                HttpResponseBuilder::server_error(format!("Failed to encode metrics: {}", err))
                    .build()
            }
        }
    } else if req.path() == "/logs" {
        use serde_json;
        let mut entries: Log = Default::default();
        for entry in export_logs(&P0) {
            entries.entries.push(LogEntry {
                timestamp: entry.timestamp,
                priority: Priority::P0,
                file: entry.file.to_string(),
                line: entry.line,
                message: entry.message,
            });
        }
        for entry in export_logs(&P1) {
            entries.entries.push(LogEntry {
                timestamp: entry.timestamp,
                priority: Priority::P1,
                file: entry.file.to_string(),
                line: entry.line,
                message: entry.message,
            });
        }
        HttpResponseBuilder::ok()
            .header("Content-Type", "application/json; charset=utf-8")
            .with_body_and_content_length(serde_json::to_string(&entries).unwrap_or_default())
            .build()
    } else {
        HttpResponseBuilder::not_found().build()
    }
}

pub fn encode_state_metrics(
    w: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>,
    // State is destructored so that if new fields
    // are added then the dev must include them in
    // the metrics or ignore them (like with config)
    State {
        blocks,
        balances,
        approvals,
        expiration_queue,
        transaction_hashes,
        transaction_timestamps,
        config: _,
        cache,
    }: &State,
) -> std::io::Result<()> {
    w.encode_gauge(
        "cycles_ledger_number_of_blocks",
        blocks.len() as f64,
        "Total number of blocks stored in the stable memory.",
    )?;
    w.encode_gauge(
        "cycles_ledger_number_of_balances",
        balances.len() as f64,
        "Total number of balances stored in the stable memory.",
    )?;
    w.encode_gauge(
        "cycles_ledger_number_of_transaction_hashes",
        transaction_hashes.len() as f64,
        "Total number of transaction hashes stored in the stable memory.",
    )?;
    w.encode_gauge(
        "cycles_ledger_number_of_transaction_timestamps",
        transaction_timestamps.len() as f64,
        "Total number of transaction timestamps stored in the stable memory.",
    )?;
    w.encode_gauge(
        "cycles_ledger_number_of_approvals",
        approvals.len() as f64,
        "Total number of approvals stored in the stable memory.",
    )?;
    w.encode_gauge(
        "cycles_ledger_number_of_approval_expiration_entries",
        expiration_queue.len() as f64,
        "Total number of approval expiration entries in the stable memory.",
    )?;
    w.encode_gauge(
        "cycles_ledger_total_supply",
        cache.total_supply as f64,
        "Total cycles supply.",
    )?;
    Ok(())
}

pub fn encode_metrics(w: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
    w.encode_gauge(
        "cycles_ledger_stable_memory_pages",
        ic_cdk::api::stable::stable_size() as f64,
        "Size of the stable memory allocated by this canister measured in 64K Wasm pages.",
    )?;
    w.encode_gauge(
        "cycles_ledger_stable_memory_bytes",
        (ic_cdk::api::stable::stable_size() * 64 * 1024) as f64,
        "Size of the stable memory allocated by this canister.",
    )?;

    let cycle_balance = ic_cdk::api::canister_balance128() as f64;
    w.encode_gauge(
        "cycles_ledger_cycle_balance",
        cycle_balance,
        "Cycle balance on this canister.",
    )?;
    w.gauge_vec("cycle_balance", "Cycle balance on this canister.")?
        .value(&[("canister", "cycles-ledger")], cycle_balance)?;

    read_state(|state| encode_state_metrics(w, state))?;

    Ok(())
}

#[query]
#[candid_method(query)]
fn icrc3_get_tip_certificate() -> Option<DataCertificate> {
    read_state(|state| state.get_tip_certificate())
}

#[query]
#[candid_method(query)]
fn icrc3_get_archives(_args: GetArchivesArgs) -> Vec<GetArchivesResult> {
    vec![]
}

fn main() {}

#[cfg(feature = "testing")]
#[query]
#[candid_method(query)]
fn get_transaction_hashes() -> std::collections::BTreeMap<[u8; 32], u64> {
    let mut res = std::collections::BTreeMap::new();
    read_state(|state| {
        for (key, (value, _maybe_canister)) in state.transaction_hashes.iter() {
            res.insert(key, value);
        }
    });
    res
}

#[cfg(feature = "testing")]
#[query]
#[candid_method(query)]
fn get_transaction_timestamps() -> std::collections::BTreeMap<(u64, u64), ()> {
    let mut res = std::collections::BTreeMap::new();
    read_state(|state| {
        for (key, value) in state.transaction_timestamps.iter() {
            res.insert(key, value);
        }
    });
    res
}

#[test]
fn test_candid_interface_compatibility() {
    use candid_parser::utils::{service_equal, CandidSource};
    use std::path::PathBuf;

    candid::export_service!();
    let exported_interface = __export_service();

    let expected_interface =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("cycles-ledger.did");

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
    .expect("The assets canister interface is not compatible with the cycles-ledger.did file");
}
