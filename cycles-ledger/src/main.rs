use candid::{candid_method, Nat};
use cycles_ledger::endpoints::{
    DataCertificate, DeduplicationError, GetTransactionsArgs, GetTransactionsResult, SendError,
};
use cycles_ledger::logs::{Log, LogEntry, Priority};
use cycles_ledger::logs::{P0, P1};
use cycles_ledger::memo::encode_send_memo;
use cycles_ledger::storage::{deduplicate, mutate_state, read_state, Operation, Transaction};
use cycles_ledger::{config, endpoints, storage, try_convert_transfer_error};
use ic_canister_log::export as export_logs;
use ic_canisters_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_cdk::api::call::{msg_cycles_accept128, msg_cycles_available128};
use ic_cdk::api::management_canister;
use ic_cdk::api::management_canister::provisional::CanisterIdRecord;
use ic_cdk_macros::{query, update};
use icrc_ledger_types::icrc::generic_metadata_value::MetadataValue;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::TransferArg as TransferArgs;
use icrc_ledger_types::icrc1::transfer::{Memo, TransferError};
use icrc_ledger_types::icrc2::allowance::{Allowance, AllowanceArgs};
use icrc_ledger_types::icrc2::approve::{ApproveArgs, ApproveError};
use icrc_ledger_types::icrc2::transfer_from::{TransferFromArgs, TransferFromError};
use num_traits::ToPrimitive;

// candid::Principal has these two consts as private
pub const CANDID_PRINCIPAL_MAX_LENGTH_IN_BYTES: usize = 29;
pub const CANDID_PRINCIPAL_SELF_AUTHENTICATING_TAG: u8 = 2;

const REMOTE_FUTURE: u64 = u64::MAX;

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
    vec![
        MetadataValue::entry("icrc1:decimals", config::DECIMALS as u64),
        MetadataValue::entry("icrc1:name", config::TOKEN_NAME),
        MetadataValue::entry("icrc1:symbol", config::TOKEN_SYMBOL),
        MetadataValue::entry("icrc1:fee", config::FEE),
    ]
}

#[query]
#[candid_method(query)]
fn icrc1_balance_of(account: Account) -> Nat {
    Nat::from(storage::balance_of(&account))
}

fn validate_memo(memo: Option<Memo>) -> Option<Memo> {
    match memo {
        Some(memo) => {
            if memo.0.len() as u64 > config::MAX_MEMO_LENGTH as u64 {
                ic_cdk::trap(&format!(
                    "memo length exceeds the maximum of {} bytes",
                    config::MAX_MEMO_LENGTH,
                ));
            }
            Some(memo)
        }
        None => None,
    }
}

#[update]
#[candid_method]
fn deposit(arg: endpoints::DepositArg) -> endpoints::DepositResult {
    let cycles_available = msg_cycles_available128();

    let amount = msg_cycles_accept128(cycles_available);
    if amount <= config::FEE {
        ic_cdk::trap("deposit amount is insufficient");
    }
    let memo = validate_memo(arg.memo);
    let (txid, balance, _phash) =
        storage::record_deposit(&arg.to, amount, memo, ic_cdk::api::time());

    endpoints::DepositResult {
        txid: Nat::from(txid),
        balance: Nat::from(balance),
    }
}

fn execute_transfer(
    from: &Account,
    to: &Account,
    spender: Option<Account>,
    amount: Nat,
    fee: Option<Nat>,
    memo: Option<Memo>,
    created_at_time: Option<u64>,
) -> Result<Nat, TransferFromError> {
    let now = ic_cdk::api::time();
    let balance = storage::balance_of(from);

    let amount = match amount.0.to_u128() {
        Some(value) => value,
        None => {
            return Err(TransferFromError::InsufficientFunds {
                balance: balance.into(),
            });
        }
    };
    let suggested_fee = match fee {
        Some(fee) => match fee.0.to_u128() {
            Some(fee) => {
                if fee != config::FEE {
                    return Err(TransferFromError::BadFee {
                        expected_fee: config::FEE.into(),
                    });
                }
                Some(fee)
            }
            None => {
                return Err(TransferFromError::BadFee {
                    expected_fee: config::FEE.into(),
                });
            }
        },
        None => None,
    };

    let memo = validate_memo(memo);

    if balance < amount.saturating_add(config::FEE) {
        return Err(TransferFromError::InsufficientFunds {
            balance: balance.into(),
        });
    }

    if let Some(spender) = spender {
        if spender != *from {
            let current_allowance = storage::allowance(from, &spender, now).0;
            if current_allowance < amount.saturating_add(config::FEE) {
                return Err(TransferFromError::InsufficientAllowance {
                    allowance: current_allowance.into(),
                });
            }
        }
    }

    // Transaction cannot be created in the future
    if let Some(time) = created_at_time {
        if time > now.saturating_add(config::PERMITTED_DRIFT.as_nanos() as u64) {
            return Err(TransferFromError::CreatedInFuture { ledger_time: now });
        }
    }

    deduplicate(
        created_at_time,
        Transaction {
            operation: Operation::Transfer {
                from: *from,
                to: *to,
                amount,
                spender,
                fee: suggested_fee,
            },
            memo: memo.clone(),
            created_at_time,
        }
        .hash(),
        now,
    )
    .map_err(|err| match err {
        DeduplicationError::TooOld => TransferFromError::TooOld,
        DeduplicationError::CreatedInFuture { ledger_time } => {
            TransferFromError::CreatedInFuture { ledger_time }
        }
        DeduplicationError::Duplicate { duplicate_of } => {
            TransferFromError::Duplicate { duplicate_of }
        }
    })?;

    let (txid, _hash) = storage::transfer(
        from,
        to,
        spender,
        amount,
        memo,
        now,
        created_at_time,
        suggested_fee,
    );

    Ok(Nat::from(txid))
}

#[update]
#[candid_method]
fn icrc1_transfer(args: TransferArgs) -> Result<Nat, TransferError> {
    let from = Account {
        owner: ic_cdk::caller(),
        subaccount: args.from_subaccount,
    };

    execute_transfer(
        &from,
        &args.to,
        None,
        args.amount,
        args.fee,
        args.memo,
        args.created_at_time,
    )
    .map_err(|err| {
        let err: TransferError = match try_convert_transfer_error(err) {
            Ok(err) => err,
            Err(err) => ic_cdk::trap(&err),
        };
        err
    })
}

#[update]
#[candid_method]
fn icrc2_transfer_from(args: TransferFromArgs) -> Result<Nat, TransferFromError> {
    let spender = Account {
        owner: ic_cdk::caller(),
        subaccount: args.spender_subaccount,
    };
    execute_transfer(
        &args.from,
        &args.to,
        Some(spender),
        args.amount,
        args.fee,
        args.memo,
        args.created_at_time,
    )
}

#[query]
#[candid_method(query)]
fn icrc3_get_transactions(args: GetTransactionsArgs) -> GetTransactionsResult {
    storage::get_transactions(args)
}

#[update]
#[candid_method]
async fn send(args: endpoints::SendArgs) -> Result<Nat, SendError> {
    let from = Account {
        owner: ic_cdk::caller(),
        subaccount: args.from_subaccount,
    };
    if args
        .to
        .as_slice()
        .get(CANDID_PRINCIPAL_MAX_LENGTH_IN_BYTES - 1)
        .map(|b| *b == CANDID_PRINCIPAL_SELF_AUTHENTICATING_TAG)
        .unwrap_or_default()
    {
        // if it is not an opaque principal ID, the user is trying to send to a non-canister target
        return Err(SendError::InvalidReceiver { receiver: args.to });
    }
    let from_key = storage::to_account_key(&from);
    let balance = storage::balance_of(&from);

    let target_canister = CanisterIdRecord {
        canister_id: args.to,
    };

    let amount = match args.amount.0.to_u128() {
        Some(value) => value,
        None => {
            return Err(SendError::InsufficientFunds {
                balance: Nat::from(balance),
            });
        }
    };

    let total_send_cost = amount.saturating_add(config::FEE);
    if total_send_cost > balance {
        return Err(SendError::InsufficientFunds {
            balance: Nat::from(balance),
        });
    }
    let memo = validate_memo(Some(encode_send_memo(&target_canister.canister_id)));

    let transaction = Transaction {
        operation: Operation::Burn { from, amount },
        memo: memo.clone(),
        created_at_time: args.created_at_time,
    };

    let now = ic_cdk::api::time();
    deduplicate(args.created_at_time, transaction.hash(), now)?;

    // While awaiting the deposit call the in-flight cycles shall not be available to the user
    mutate_state(now, |s| s.debit(from_key, total_send_cost));
    let deposit_cycles_result =
        management_canister::main::deposit_cycles(target_canister, amount).await;
    // Revert deduction of in-flight cycles. 'Real' deduction happens in storage::send
    mutate_state(now, |s| s.credit(from_key, total_send_cost));

    if let Err((rejection_code, rejection_reason)) = deposit_cycles_result {
        let now = ic_cdk::api::time();
        let fee_block = storage::penalize(&from, now).map(|(fee_block, _block_hash)| fee_block);
        Err(SendError::FailedToSend {
            fee_block,
            rejection_code,
            rejection_reason,
        })
    } else {
        let (send, _send_hash) = storage::send(&from, amount, memo, now, args.created_at_time);
        Ok(send)
    }
}

#[query]
#[candid_method(query)]
fn icrc2_allowance(args: AllowanceArgs) -> Allowance {
    let allowance = storage::allowance(&args.account, &args.spender, ic_cdk::api::time());
    let mut expires_at = None;
    if allowance.1 > 0 {
        expires_at = Some(allowance.1);
    }
    Allowance {
        allowance: Nat::from(allowance.0),
        expires_at,
    }
}

#[update]
#[candid_method]
fn icrc2_approve(args: ApproveArgs) -> Result<Nat, ApproveError> {
    let now = ic_cdk::api::time();

    let from_account = Account {
        owner: ic_cdk::api::caller(),
        subaccount: args.from_subaccount,
    };
    if from_account.owner == args.spender.owner {
        ic_cdk::trap("self approval is not allowed")
    }
    let memo = validate_memo(args.memo);
    let amount = match args.amount.0.to_u128() {
        Some(value) => value,
        None => u128::MAX,
    };
    let current_allowance = storage::allowance(&from_account, &args.spender, now).0;
    let expected_allowance = match args.expected_allowance {
        Some(n) => match n.0.to_u128() {
            Some(n) => {
                if n != current_allowance {
                    return Err(ApproveError::AllowanceChanged {
                        current_allowance: current_allowance.into(),
                    });
                }
                Some(n)
            }
            None => {
                return Err(ApproveError::AllowanceChanged {
                    current_allowance: current_allowance.into(),
                });
            }
        },
        None => None,
    };
    let suggested_fee = match args.fee {
        Some(fee) => match fee.0.to_u128() {
            Some(fee) => {
                if fee != config::FEE {
                    return Err(ApproveError::BadFee {
                        expected_fee: Nat::from(config::FEE),
                    });
                }
                Some(fee)
            }
            None => {
                return Err(ApproveError::BadFee {
                    expected_fee: Nat::from(config::FEE),
                });
            }
        },
        None => None,
    };

    let balance = storage::balance_of(&from_account);
    if balance < config::FEE {
        return Err(ApproveError::InsufficientFunds {
            balance: Nat::from(balance),
        });
    }

    // Approvals cannot be created in the future
    if let Some(time) = args.created_at_time {
        if time > now.saturating_add(config::PERMITTED_DRIFT.as_nanos() as u64) {
            return Err(ApproveError::CreatedInFuture { ledger_time: now });
        }
    }

    if args.expires_at.unwrap_or(REMOTE_FUTURE) <= now {
        return Err(ApproveError::Expired { ledger_time: now });
    }

    let txid = storage::approve(
        (&from_account, &args.spender),
        amount,
        args.expires_at,
        now,
        expected_allowance,
        memo,
        args.created_at_time,
        suggested_fee,
    );

    Ok(Nat::from(txid))
}

#[candid_method(query)]
#[query]
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

    w.encode_gauge(
        "cycles_ledger_number_of_blocks",
        read_state(|state| state.blocks.len()) as f64,
        "Total number of blocks stored in the stable memory.",
    )?;
    Ok(())
}

#[query]
#[candid_method(query)]
fn icrc3_get_tip_certificate() -> Option<DataCertificate> {
    read_state(|state| state.get_tip_certificate())
}

fn main() {}

#[cfg(feature = "testing")]
#[query]
#[candid_method(query)]
fn get_transaction_hashes() -> std::collections::BTreeMap<[u8; 32], u64> {
    let mut res = std::collections::BTreeMap::new();
    read_state(|state| {
        for (key, value) in state.transaction_hashes.iter() {
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
    use candid::utils::{service_compatible, CandidSource};
    use std::path::PathBuf;

    candid::export_service!();
    let new_interface = __export_service();

    let old_interface =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("cycles-ledger.did");

    println!("Exported interface: {}", new_interface);

    service_compatible(
        CandidSource::Text(&new_interface),
        CandidSource::File(old_interface.as_path()),
    )
    .expect("The assets canister interface is not compatible with the cycles-ledger.did file");
}
