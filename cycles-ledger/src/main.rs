use candid::{candid_method, Nat};
use cycles_ledger::memo::SendMemo;
use cycles_ledger::storage::mutate_state;
use cycles_ledger::Account;
use cycles_ledger::{config, endpoints, storage};
use ic_cdk::api::call::{msg_cycles_accept128, msg_cycles_available128};
use ic_cdk::api::management_canister;
use ic_cdk::api::management_canister::provisional::CanisterIdRecord;
use ic_cdk_macros::{query, update};
use minicbor::Encoder;
use num_traits::ToPrimitive;

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
    vec![endpoints::SupportedStandard {
        name: "ICRC-1".to_string(),
        url: "https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-1/README.md".to_string(),
    }]
}

#[query]
#[candid_method(query)]
fn icrc1_total_supply() -> Nat {
    // TODO(FI-765): Implement the total supply function.
    todo!()
}

#[query]
#[candid_method(query)]
fn icrc1_metadata() -> Vec<(String, endpoints::Value)> {
    vec![
        endpoints::make_entry("icrc1:decimals", config::DECIMALS),
        endpoints::make_entry("icrc1:fee", config::FEE),
        endpoints::make_entry("icrc1:name", config::TOKEN_NAME),
        endpoints::make_entry("icrc1:symbol", config::TOKEN_SYMBOL),
    ]
}

#[query]
#[candid_method(query)]
fn icrc1_balance_of(account: Account) -> Nat {
    Nat::from(storage::balance_of(&account))
}

fn validate_memo(memo: Option<endpoints::Memo>) -> Option<endpoints::Memo> {
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

    // TODO(FI-767): Implement deduplication.

    let amount = msg_cycles_accept128(cycles_available);
    if amount <= config::FEE {
        ic_cdk::trap("deposit amount is insufficient to cover fees");
    }
    let memo = validate_memo(arg.memo);
    let (txid, balance, _phash) =
        storage::record_deposit(&arg.to, amount, memo, ic_cdk::api::time());

    // TODO(FI-766): set the certified variable.

    endpoints::DepositResult {
        txid: Nat::from(txid),
        balance: Nat::from(balance),
    }
}

#[update]
#[candid_method]
fn icrc1_transfer(args: endpoints::TransferArg) -> Result<Nat, endpoints::TransferError> {
    let from = Account {
        owner: ic_cdk::caller(),
        subaccount: args.from_subaccount,
    };
    let now = ic_cdk::api::time();
    let balance = storage::balance_of(&from);

    // TODO(FI-767): Implement deduplication.

    let amount = match args.amount.0.to_u128() {
        Some(value) => value,
        None => {
            return Err(endpoints::TransferError::InsufficientFunds {
                balance: Nat::from(balance),
            });
        }
    };
    if let Some(fee) = args.fee {
        match fee.0.to_u128() {
            Some(fee) => {
                if fee != config::FEE {
                    return Err(endpoints::TransferError::BadFee {
                        expected_fee: Nat::from(config::FEE),
                    });
                }
            }
            None => {
                return Err(endpoints::TransferError::BadFee {
                    expected_fee: Nat::from(config::FEE),
                });
            }
        }
    }
    let memo = validate_memo(args.memo);

    if balance < amount.saturating_add(config::FEE) {
        return Err(endpoints::TransferError::InsufficientFunds {
            balance: Nat::from(balance),
        });
    }

    let (txid, _hash) = storage::transfer(&from, &args.to, amount, memo, now);

    Ok(Nat::from(txid))
}

#[update]
#[candid_method]
async fn send(args: endpoints::SendArg) -> Result<Nat, endpoints::SendError> {
    if args
        .to
        .as_slice()
        .get(28) // candid::Principal::MAX_LENGTH_IN_BYTES - 1
        .map(|b| *b == 2) // candid::Principal::SELF_AUTHENTICATING_TAG
        .unwrap_or_default()
    {
        // self-authenticating ID means user is trying to send to a non-canister target
        return Err(endpoints::SendError::InvalidReceiver { receiver: args.to });
    }
    let from = Account {
        owner: ic_cdk::caller(),
        subaccount: args.from_subaccount,
    };
    let from_key = storage::to_account_key(&from);
    let now = ic_cdk::api::time();
    let balance = storage::balance_of(&from);

    let target_canister = CanisterIdRecord {
        canister_id: args.to,
    };

    // TODO(FI-767): Implement deduplication.

    let amount = match args.amount.0.to_u128() {
        Some(value) => value,
        None => {
            return Err(endpoints::SendError::InsufficientFunds {
                balance: Nat::from(balance),
            });
        }
    };
    if let Some(fee) = args.fee {
        match fee.0.to_u128() {
            Some(fee) => {
                if fee != config::FEE {
                    return Err(endpoints::SendError::BadFee {
                        expected_fee: Nat::from(config::FEE),
                    });
                }
            }
            None => {
                return Err(endpoints::SendError::BadFee {
                    expected_fee: Nat::from(config::FEE),
                });
            }
        }
    }
    let total_send_cost = amount.saturating_add(config::FEE);
    if total_send_cost > balance {
        return Err(endpoints::SendError::InsufficientFunds {
            balance: Nat::from(balance),
        });
    }
    let memo = SendMemo {
        receiver: target_canister.canister_id.as_slice(),
    };
    let mut encoder = Encoder::new(Vec::new());
    encoder.encode(memo).expect("Encoding failed");
    let encoded_memo = encoder.into_writer().into();
    let memo = validate_memo(Some(encoded_memo));

    // While awaiting the deposit call the in-flight cycles shall not be available to the user
    mutate_state(|s| {
        let new_balance = balance - total_send_cost;
        if new_balance == Nat::from(0) {
            s.balances.remove(&from_key);
        } else {
            s.balances.insert(from_key, new_balance);
        }
    });
    let deposit_cycles_result =
        management_canister::main::deposit_cycles(target_canister, amount).await;
    // Revert in-flight deduction. 'Real' deduction happens in storage::send
    let balance = storage::balance_of(&from);
    mutate_state(|s| {
        let new_balance = balance + total_send_cost;
        s.balances.insert(from_key, new_balance);
    });

    if let Err((rejection_code, rejection_reason)) = deposit_cycles_result {
        let (fee, _fee_hash) = storage::send(&from, 0, memo, now);
        Err(endpoints::SendError::FailedToSend {
            fee,
            rejection_code,
            rejection_reason,
        })
    } else {
        let (send, _send_hash) = storage::send(&from, amount, memo, now);
        Ok(send)
    }
}

fn main() {}

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
