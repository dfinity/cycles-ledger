use std::{collections::HashMap, sync::Arc};

use candid::{CandidType, Decode, Encode, Nat, Principal};
use cycles_ledger::{
    config::FEE,
    endpoints::{DepositArg, DepositResult, SendArgs, SendError},
};
use ic_test_state_machine_client::{StateMachine, WasmResult};
use icrc_ledger_types::{
    icrc1::{
        account::Account,
        transfer::{Memo, TransferArg, TransferError},
    },
    icrc2::{
        approve::{ApproveArgs, ApproveError},
        transfer_from::TransferFromArgs,
    },
};
use num_traits::ToPrimitive;
use proptest::{
    collection, option,
    prelude::any,
    prop_assert_eq, prop_compose, proptest,
    sample::select,
    strategy::{Just, Strategy, Union},
};
use serde::Deserialize;
use serde_bytes::ByteBuf;

// The arguments passed to an update call to the cycles ledger.
#[derive(Clone, Debug)]
pub enum CyclesLedgerCallArg {
    Approve(ApproveArgs),
    Deposit { amount: Nat, arg: DepositArg },
    Send(SendArgs),
    Transfer(TransferArg),
    TransferFrom(TransferFromArgs),
}

impl From<ApproveArgs> for CyclesLedgerCallArg {
    fn from(value: ApproveArgs) -> Self {
        Self::Approve(value)
    }
}

impl From<(Nat, DepositArg)> for CyclesLedgerCallArg {
    fn from((amount, arg): (Nat, DepositArg)) -> Self {
        Self::Deposit { amount, arg }
    }
}

impl From<SendArgs> for CyclesLedgerCallArg {
    fn from(value: SendArgs) -> Self {
        Self::Send(value)
    }
}

impl From<TransferArg> for CyclesLedgerCallArg {
    fn from(value: TransferArg) -> Self {
        Self::Transfer(value)
    }
}

impl From<TransferFromArgs> for CyclesLedgerCallArg {
    fn from(value: TransferFromArgs) -> Self {
        Self::TransferFrom(value)
    }
}

// An update call to the Cycle Ledger.
#[derive(Clone, Debug)]
pub struct CyclesLedgerCall {
    caller: Principal,
    arg: CyclesLedgerCallArg,
}

impl std::fmt::Display for CyclesLedgerCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn encode_memo(memo: &Option<Memo>) -> Option<String> {
            memo.as_ref().map(|bs| hex::encode(bs.0.as_slice()))
        }

        fn encode_account(owner: Principal, subaccount: Option<[u8; 32]>) -> String {
            Account { owner, subaccount }.to_string()
        }

        match &self.arg {
            CyclesLedgerCallArg::Approve(arg) => {
                write!(f, "Approve {{ ")?;
                write!(
                    f,
                    "from: {}, ",
                    encode_account(self.caller, arg.from_subaccount)
                )?;
                write!(f, "spender: {}, ", arg.spender)?;
                write!(f, "amount: {}, ", arg.amount)?;
                write!(f, "expected_allowance: {:?}, ", arg.expected_allowance)?;
                write!(f, "expires_at: {:?}, ", arg.expires_at)?;
                write!(f, "fee: {:?}, ", arg.fee)?;
                write!(f, "memo: {:?}, ", encode_memo(&arg.memo))?;
                write!(f, "created_at_time: {:?} ", arg.created_at_time)?;
                write!(f, "}}")
            }
            CyclesLedgerCallArg::Deposit { amount, arg } => {
                write!(f, "Deposit {{ ")?;
                write!(f, "from: {}, ", self.caller)?;
                write!(f, "to: {}, ", arg.to)?;
                write!(f, "amount: {}, ", amount)?;
                write!(f, "memo:: {:?} ", encode_memo(&arg.memo))?;
                write!(f, "}}")
            }
            CyclesLedgerCallArg::Send(arg) => {
                write!(f, "Send {{ ")?;
                write!(
                    f,
                    "from, {}, ",
                    encode_account(self.caller, arg.from_subaccount)
                )?;
                write!(f, "to: {}, ", arg.to)?;
                write!(f, "amount: {}, ", arg.amount)?;
                write!(f, "created_at_time: {:?} ", arg.created_at_time)?;
                write!(f, "}}")
            }
            CyclesLedgerCallArg::Transfer(arg) => {
                write!(f, "Transfer {{ ")?;
                write!(
                    f,
                    "from, {}, ",
                    encode_account(self.caller, arg.from_subaccount)
                )?;
                write!(f, "to: {}, ", arg.to)?;
                write!(f, "amount: {}, ", arg.amount)?;
                write!(f, "created_at_time: {:?} ", arg.created_at_time)?;
                write!(f, "fee: {:?}, ", arg.fee)?;
                write!(f, "memo: {:?} ", encode_memo(&arg.memo))?;
                write!(f, "}}")
            }
            CyclesLedgerCallArg::TransferFrom(arg) => {
                write!(f, "TransferFrom {{ ")?;
                write!(f, "from, {}, ", arg.from)?;
                write!(f, "to: {}, ", arg.to)?;
                write!(
                    f,
                    "spender: {}, ",
                    encode_account(self.caller, arg.spender_subaccount)
                )?;
                write!(f, "amount: {}, ", arg.amount)?;
                write!(f, "created_at_time: {:?} ", arg.created_at_time)?;
                write!(f, "fee: {:?}, ", arg.fee)?;
                write!(f, "memo: {:?} ", encode_memo(&arg.memo))?;
                write!(f, "}}")
            }
        }
    }
}

pub trait CyclesLedgerApplyCall {
    fn apply(&mut self, call: &CyclesLedgerCall) -> Result<(), String>;
}

fn update_call<I, O>(
    env: &StateMachine,
    canister_id: Principal,
    caller: Principal,
    method: &str,
    arg: &I,
) -> Result<O, String>
where
    I: CandidType,
    O: CandidType + for<'a> Deserialize<'a>,
{
    if let WasmResult::Reply(res) = env
        .update_call(canister_id, caller, method, Encode!(arg).unwrap())
        .map_err(|e| format!("call to {} failed: {}", method, e))?
    {
        Decode!(&res, O).map_err(|e| format!("call to {} failed: {}", method, e))
    } else {
        panic!("call to {} rejected", method)
    }
}

// A cycles-ledger and depositor cannisters installed on a [StateMachine].
#[derive(Clone)]
pub struct CyclesLedgerInStateMachine<'a> {
    pub env: &'a StateMachine,
    pub ledger_id: Principal,
    pub depositor_id: Principal,
}

impl<'a> CyclesLedgerApplyCall for CyclesLedgerInStateMachine<'a> {
    fn apply(&mut self, call: &CyclesLedgerCall) -> Result<(), String> {
        use CyclesLedgerCallArg::*;

        match &call.arg {
            Approve(arg) => {
                let _ = update_call::<_, Result<Nat, ApproveError>>(
                    self.env,
                    self.ledger_id,
                    call.caller.to_owned(),
                    "icrc2_approve",
                    arg,
                )?
                .map_err(|e| {
                    format!(
                        "call to approve(from:{}, spender:{}, amount:{}) failed: {:?}",
                        Account {
                            owner: call.caller,
                            subaccount: arg.from_subaccount
                        },
                        arg.spender,
                        arg.amount,
                        e,
                    )
                })?;
            }
            Send(arg) => {
                let _ = update_call::<_, Result<Nat, SendError>>(
                    self.env,
                    self.ledger_id,
                    call.caller,
                    "send",
                    arg,
                )?
                .map_err(|e| {
                    format!(
                        "call to send(from:{}, to:{}, amount:{}) failed: {:?}",
                        Account {
                            owner: call.caller,
                            subaccount: arg.from_subaccount
                        },
                        arg.to,
                        arg.amount,
                        e,
                    )
                })?;
            }
            Transfer(arg) => {
                let _ = update_call::<_, Result<Nat, TransferError>>(
                    self.env,
                    self.ledger_id,
                    call.caller,
                    "icrc1_transfer",
                    arg,
                )?
                .map_err(|e| {
                    format!(
                        "call to icrc1_transfer(from:{}, to:{}, amount:{}) failed: {}",
                        Account {
                            owner: call.caller,
                            subaccount: arg.from_subaccount
                        },
                        arg.to,
                        arg.amount,
                        e,
                    )
                })?;
            }
            TransferFrom(arg) => {
                let _ = update_call::<_, Result<Nat, TransferError>>(
                    self.env,
                    self.ledger_id,
                    call.caller,
                    "icrc2_transfer_from",
                    arg
                )?
                .map_err(|e|
                    format!("call to icrc2_transfer_from(from:{}, spender:{}, to:{}, amount:{}) failed: {}",
                        arg.from,
                        Account { owner: call.caller, subaccount: arg.spender_subaccount },
                        arg.to,
                        arg.amount,
                        e,
                    )
                )?;
            }
            Deposit { amount, arg } => {
                let cycles = amount.0.to_u128().unwrap();
                let arg = depositor::endpoints::DepositArg {
                    to: arg.to.to_owned(),
                    memo: arg.memo.to_owned(),
                    cycles,
                };
                let _ = update_call::<_, DepositResult>(
                    self.env,
                    self.depositor_id,
                    call.caller,
                    "deposit",
                    &arg,
                )?;
            }
        };
        Ok(())
    }
}

// An in-memory cycles ledger state.
#[derive(Clone, Debug, Default)]
pub struct CyclesLedgerInMemory {
    pub balances: HashMap<Account, u128>,
    pub allowances: HashMap<(Account, Account), u128>,
    pub total_supply: u128,
    pub depositor_cycles: u128,
}

impl CyclesLedgerInMemory {
    pub fn new(depositor_cycles: u128) -> Self {
        Self {
            depositor_cycles,
            ..Default::default()
        }
    }

    pub fn token_pool(&self) -> u128 {
        u128::MAX - self.total_supply
    }
}

impl CyclesLedgerApplyCall for CyclesLedgerInMemory {
    fn apply(&mut self, arg: &CyclesLedgerCall) -> Result<(), String> {
        match &arg.arg {
            CyclesLedgerCallArg::Approve(ApproveArgs {
                from_subaccount,
                spender,
                amount,
                ..
            }) => {
                let from = Account {
                    owner: arg.caller,
                    subaccount: *from_subaccount,
                };
                let old_balance = self
                    .balances
                    .get(&from)
                    .ok_or_else(|| format!("Account {} has 0 balance", from))?;
                self.balances.insert(
                    from,
                    old_balance
                        .checked_sub(FEE)
                        .ok_or("unable to subtract the fee")?,
                );
                self.allowances.insert(
                    (from, *spender),
                    amount.0.to_u128().ok_or("amount is not a u128")?,
                );
                self.total_supply = self
                    .total_supply
                    .checked_sub(FEE)
                    .ok_or("total supply underflow")?;
            }
            CyclesLedgerCallArg::Deposit {
                amount,
                arg: DepositArg { to, .. },
            } => {
                let amount = amount.0.to_u128().ok_or("amount is not a u128")?;
                // The precise cost of calling the deposit endpoint is unknown.
                // depositor_cycles is decreased by an arbitrary number plus
                // the amount.
                self.depositor_cycles = self
                    .depositor_cycles
                    .saturating_sub(10_000_000_000_000u128.saturating_add(amount));

                let old_balance = self.balances.get(to).copied().unwrap_or_default();
                self.balances
                    .insert(*to, old_balance.checked_add(amount).ok_or("overflow")?);
                self.total_supply = self
                    .total_supply
                    .checked_add(amount)
                    .ok_or("total supply overflow")?;
            }
            CyclesLedgerCallArg::Send(SendArgs {
                from_subaccount,
                amount,
                ..
            }) => {
                let from = Account {
                    owner: arg.caller,
                    subaccount: *from_subaccount,
                };
                let old_balance = self
                    .balances
                    .get(&from)
                    .ok_or_else(|| format!("Account {} has 0 balance", from))?;
                let amount = amount.0.to_u128().ok_or("amount is not a u128")?;
                let amount_plus_fee = amount.checked_add(FEE).ok_or("amount + FEE overflow")?;
                self.balances.insert(
                    from,
                    old_balance
                        .checked_sub(amount_plus_fee)
                        .ok_or("balance underflow")?,
                );
                self.total_supply = self
                    .total_supply
                    .checked_sub(amount_plus_fee)
                    .ok_or("total supply undeflow")?;
            }
            CyclesLedgerCallArg::Transfer(TransferArg {
                from_subaccount,
                to,
                amount,
                ..
            }) => {
                let from = Account {
                    owner: arg.caller,
                    subaccount: *from_subaccount,
                };
                let old_balance = self
                    .balances
                    .get(&from)
                    .ok_or_else(|| format!("Account {} has 0 balance", from))?;
                let amount = amount.0.to_u128().ok_or("amount is not a u128")?;
                let new_balance = old_balance
                    .checked_sub(amount)
                    .and_then(|b| b.checked_sub(FEE))
                    .ok_or("balance underflow")?;
                self.balances.insert(from, new_balance);
                let old_balance = self.balances.get(to).copied().unwrap_or_default();
                self.balances.insert(
                    *to,
                    old_balance.checked_add(amount).ok_or("balance overflow")?,
                );
                self.total_supply = self
                    .total_supply
                    .checked_sub(FEE)
                    .ok_or("total supply underflow")?;
            }
            CyclesLedgerCallArg::TransferFrom(TransferFromArgs {
                spender_subaccount,
                from,
                to,
                amount,
                fee,
                memo,
                created_at_time,
            }) => {
                self.apply(&CyclesLedgerCall {
                    caller: from.owner,
                    arg: CyclesLedgerCallArg::Transfer(TransferArg {
                        from_subaccount: from.subaccount,
                        to: *to,
                        fee: fee.to_owned(),
                        created_at_time: *created_at_time,
                        memo: memo.to_owned(),
                        amount: amount.clone(),
                    }),
                })?;
                let spender = Account {
                    owner: arg.caller,
                    subaccount: *spender_subaccount,
                };
                let old_allowance = self
                    .allowances
                    .get(&(*from, spender))
                    .unwrap_or_else(|| panic!("Allowance of {:?} is 0", (from, spender)));
                let amount = amount.0.to_u128().ok_or("amount is not a u128")?;
                let new_allowance = old_allowance
                    .checked_sub(amount)
                    .and_then(|b| b.checked_sub(FEE))
                    .ok_or("allowance underflow")?;
                self.allowances.insert((*from, spender), new_allowance);
            }
        }
        Ok(())
    }
}

// Represents a set of valid calls and the
// in-memory state that results when performing those
// calls.
#[derive(Clone, Debug, Default)]
pub struct CyclesLedgerCallsState {
    pub calls: Vec<CyclesLedgerCall>,
    pub state: CyclesLedgerInMemory,
}

impl CyclesLedgerCallsState {
    fn new(depositor_cycles: u128) -> Self {
        Self {
            calls: vec![],
            state: CyclesLedgerInMemory::new(depositor_cycles),
        }
    }

    // Return the number of tokens available for minting
    fn token_pool(&self) -> u128 {
        self.state.token_pool()
    }

    fn accounts_with_at_least_fee(&self) -> Vec<(Account, u128)> {
        self.state
            .balances
            .iter()
            .filter_map(|(account, balance)| {
                if balance >= &FEE {
                    Some((*account, *balance))
                } else {
                    None
                }
            })
            .collect()
    }
}

impl CyclesLedgerApplyCall for CyclesLedgerCallsState {
    fn apply(&mut self, arg: &CyclesLedgerCall) -> Result<(), String> {
        self.state.apply(arg)?;
        self.calls.push(arg.clone());
        Ok(())
    }
}

fn arb_allowed_principal() -> impl Strategy<Value = Principal> {
    collection::vec(any::<u8>(), 0..30).prop_filter_map(
        "Management and anonymous principals are disabled",
        |bytes| {
            let principal = Principal::from_slice(&bytes);
            if principal == Principal::management_canister() || principal == Principal::anonymous()
            {
                None
            } else {
                Some(principal)
            }
        },
    )
}

fn arb_account() -> impl Strategy<Value = Account> {
    (arb_allowed_principal(), option::of(any::<[u8; 32]>()))
        .prop_map(|(owner, subaccount)| Account { owner, subaccount })
}

fn arb_amount(max: u128) -> impl Strategy<Value = Nat> {
    (0..=max).prop_map(Nat::from)
}

fn arb_memo() -> impl Strategy<Value = Memo> {
    collection::vec(any::<u8>(), 0..32).prop_map(|bytes| Memo(ByteBuf::from(bytes)))
}

fn arb_approve(
    token_pool: u128,
    allowances: Arc<HashMap<(Account, Account), u128>>,
    arb_approver: impl Strategy<Value = Account>,
) -> impl Strategy<Value = CyclesLedgerCall> {
    (arb_approver, arb_account(), arb_amount(token_pool))
        .prop_filter("self-approve disabled", |(approver, spender, _)| {
            approver.owner != spender.owner
        })
        .prop_flat_map(move |(approver, spender, amount)| {
            let allowance = allowances
                .get(&(approver, spender))
                .copied()
                .unwrap_or_default();
            let arb_expected_allowance = option::of(Just(allowance.into()));
            let arb_suggested_fee = option::of(Just(FEE.into()));
            (
                option::of(arb_memo()),
                arb_expected_allowance,
                arb_suggested_fee,
            )
                .prop_map(move |(memo, expected_allowance, fee)| CyclesLedgerCall {
                    caller: approver.owner,
                    arg: ApproveArgs {
                        from_subaccount: approver.subaccount,
                        spender,
                        amount: amount.clone(),
                        expected_allowance,
                        expires_at: None, // TODO
                        fee,
                        memo,
                        created_at_time: None, // TODO
                    }
                    .into(),
                })
        })
}

prop_compose! {
    fn arb_deposit(depositor: Principal, depositor_cycles: u128)
                  (to in arb_account(),
                  // deposit requires that the amount is >= FEE
                   amount in arb_amount(depositor_cycles - FEE).prop_map(|c| c + Nat::from(FEE)),
                   memo in option::of(arb_memo()),
                  )
                  -> CyclesLedgerCall {
        CyclesLedgerCall {
            caller: depositor,
            arg: (amount, DepositArg { to, memo, }).into()
        }
    }
}

prop_compose! {
    fn arb_send(arb_from: impl Strategy<Value = (Account, u128)>, depositor: Principal)
               ((from, from_balance) in arb_from)
               (from in Just(from),
                amount in (0..=(from_balance - FEE)).prop_map(Nat::from),
               )
               -> CyclesLedgerCall {
        CyclesLedgerCall {
            caller: from.owner,
            arg: SendArgs {
                from_subaccount: from.subaccount,
                // Destination must exist so we pass the only
                // canister that we know exists except for the Ledger.
                to: depositor,
                created_at_time: None, // TODO
                amount
            }.into(),
        }
    }
}

prop_compose! {
    fn arb_transfer(arb_from: impl Strategy<Value = (Account, u128)>)
                   ((from, from_balance) in arb_from)
                   (from in Just(from),
                    to in arb_account().prop_filter("cannot self tranasfer", move |to| &from != to),
                    fee in option::of(Just(FEE.into())),
                    amount in (0..=(from_balance-FEE)).prop_map(Nat::from),
                    memo in option::of(arb_memo()),
                   )
                   -> CyclesLedgerCall {
        CyclesLedgerCall {
            caller: from.owner,
            arg: TransferArg {
                from_subaccount: from.subaccount,
                to,
                fee,
                created_at_time: None,
                memo,
                amount
            }.into(),
        }
    }
}

prop_compose! {
    fn arb_transfer_from(arb_from_spender: impl Strategy<Value = (Account, Account, u128)>)
                        ((from, spender, from_balance) in arb_from_spender)
                        (from in Just(from),
                         spender in Just(spender),
                         to in arb_account().prop_filter("cannot self tranasfer", move |to| &from != to),
                         fee in option::of(Just(FEE.into())),
                         amount in (0..=(from_balance-FEE)).prop_map(Nat::from),
                         memo in option::of(arb_memo()),
                        )
                        -> CyclesLedgerCall {
        CyclesLedgerCall {
            caller: spender.owner,
            arg: TransferFromArgs {
                from,
                to,
                spender_subaccount: spender.subaccount,
                fee,
                created_at_time: None,
                memo,
                amount,
            }.into(),
        }
    }
}

pub fn arb_cycles_ledger_call_state(
    depositor: Principal,
    depositor_cycles: u128,
    len: u8,
) -> impl Strategy<Value = CyclesLedgerCallsState> {
    if depositor_cycles < FEE {
        panic!(
            "Cannot run the test if the depositor doesn't have enough cycles for the first deposit"
        );
    }
    arb_cycles_ledger_call_state_from(
        CyclesLedgerCallsState::new(depositor_cycles),
        depositor,
        len,
    )
}

// Note(mp): this genereator will blow up the stack for high `len`
// because it will call itself recursively `len` times. If you need a bigger
// state then do multiple sequential calls to
// [arb_cycles_ledger_call_state_from].
pub fn arb_cycles_ledger_call_state_from(
    state: CyclesLedgerCallsState,
    depositor_id: Principal,
    len: u8,
) -> impl Strategy<Value = CyclesLedgerCallsState> {
    fn step(
        state: CyclesLedgerCallsState,
        depositor: Principal,
        n: u8,
    ) -> impl Strategy<Value = CyclesLedgerCallsState> {
        if n == 0 {
            return Just(state).boxed();
        }

        let accounts = state.accounts_with_at_least_fee();
        let allowances = Arc::new(state.state.allowances.clone());
        let depositor_cycles = state.state.depositor_cycles;
        let token_pool = state.token_pool();

        let mut arb_calls = vec![];
        if depositor_cycles > 0 {
            let arb_deposit = arb_deposit(depositor, depositor_cycles);
            arb_calls.push(arb_deposit.boxed());
        }
        if !accounts.is_empty() {
            let select_account_and_balance = Arc::new(select(accounts.clone()));

            // approve
            let select_account = select_account_and_balance.clone().prop_map(|(a, _)| a);
            let arb_approve = arb_approve(token_pool, allowances.clone(), select_account);
            arb_calls.push(arb_approve.boxed());

            // send
            let arb_send = arb_send(select_account_and_balance.clone(), depositor);
            arb_calls.push(arb_send.boxed());

            // transfer
            let arb_transfer = arb_transfer(select_account_and_balance);
            arb_calls.push(arb_transfer.boxed());

            // transfer_from
            let accounts: HashMap<_, _> = accounts.iter().copied().collect();
            let mut from_spender_amount = vec![];
            for ((from, spender), allowance) in allowances.as_ref() {
                let Some(balance) = accounts.get(from) else { continue; };
                from_spender_amount.push((*from, *spender, *allowance.min(balance)));
            }
            if !from_spender_amount.is_empty() {
                let arb_transfer_from = arb_transfer_from(select(from_spender_amount));
                arb_calls.push(arb_transfer_from.boxed());
            }
        }

        if arb_calls.is_empty() {
            panic!("BUG: no valid call can be performed on the current state");
        }

        // Union panics if arb_calls is empty but it shouldn't be
        // as either the depositor has cycles or an account has funds.
        (Union::new(arb_calls), Just(state))
            .prop_flat_map(move |(call, mut state)| {
                state.apply(&call).unwrap();
                step(state, depositor, n - 1)
            })
            .boxed()
    }

    step(state, depositor_id, len)
}

#[test]
fn test() {
    // check that [arb_cycles_ledger_call_state] doesn't panic
    proptest!(|(state in arb_cycles_ledger_call_state(Principal::anonymous(), u128::MAX, 10))| {
        prop_assert_eq!(10, state.calls.len())
    })
}
