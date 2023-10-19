use std::{collections::HashMap, sync::Arc};

use candid::{Principal, Nat};
use cycles_ledger::{storage::Block, endpoints::{SendArgs, DepositArg}, config::FEE};
use icrc_ledger_types::{icrc1::{account::Account, transfer::{TransferArg, Memo}}, icrc2::{approve::ApproveArgs, transfer_from::TransferFromArgs}};
use num_traits::ToPrimitive;
use proptest::{strategy::{Strategy, Just, Union}, prop_compose, prelude::any, option, collection, proptest, prop_assert_eq, sample::select};
use serde_bytes::ByteBuf;

#[derive(Clone, Debug)]
pub enum CyclesLedgerCallArg {
    Approve(ApproveArgs),
    Deposit {
        amount: Nat,
        arg: DepositArg,
    },
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

#[derive(Clone, Debug)]
pub struct CyclesLedgerCall {
    caller: Principal,
    arg: CyclesLedgerCallArg,
}

impl From<Block> for CyclesLedgerCall {
    fn from(block: Block) -> Self {
        use cycles_ledger::storage::Operation::*;

        match block.transaction.operation {
            Mint { to, amount } =>
                CyclesLedgerCall {
                    // random bc the depositor is not persisted
                    caller: Principal::from_slice(&[123]),
                    arg: CyclesLedgerCallArg::Deposit {
                        amount: Nat::from(amount),
                        arg: DepositArg { to, memo: block.transaction.memo }
                    }
                },
            Transfer { from, to, spender: Some(spender), amount, fee } =>
                CyclesLedgerCall {
                    caller: spender.owner,
                    arg: CyclesLedgerCallArg::TransferFrom(TransferFromArgs {
                        spender_subaccount: spender.subaccount,
                        from,
                        to,
                        created_at_time: block.transaction.created_at_time,
                        memo: block.transaction.memo,
                        amount: Nat::from(amount),
                        fee: fee.map(Nat::from),
                    })
                },
            Transfer { from, to, spender: _, amount, fee } =>
                CyclesLedgerCall {
                    caller: from.owner,
                    arg: CyclesLedgerCallArg::Transfer(TransferArg {
                        from_subaccount: from.subaccount,
                        to,
                        created_at_time: block.transaction.created_at_time,
                        memo: block.transaction.memo,
                        amount: Nat::from(amount),
                        fee: fee.map(Nat::from),
                    })
                },
            Burn { from, amount } =>
                CyclesLedgerCall {
                    caller: from.owner,
                    arg: CyclesLedgerCallArg::Send(SendArgs { 
                        from_subaccount: from.subaccount,
                        to: Principal::from_slice(block.transaction.memo
                            .expect("Memo should be set in send block")
                            .0.as_slice()),
                        created_at_time: block.transaction.created_at_time,
                        amount: Nat::from(amount),
                    })
                },
            Approve { from, spender, amount, expected_allowance, expires_at, fee } =>
                CyclesLedgerCall {
                    caller: from.owner,
                    arg: CyclesLedgerCallArg::Approve(ApproveArgs {
                        from_subaccount: from.subaccount,
                        spender,
                        amount: Nat::from(amount),
                        expected_allowance: expected_allowance.map(Nat::from),
                        expires_at,
                        fee: fee.map(Nat::from),
                        memo: block.transaction.memo,
                        created_at_time: block.transaction.created_at_time,
                    }),
                },
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct CyclesLedgerState {
    pub balances: HashMap<Account, u128>,
    pub allowances: HashMap<(Account, Account), u128>,
    pub token_supply: u128,
}

impl CyclesLedgerState {
    fn token_pool(&self) -> u128 {
        u128::MAX - self.token_supply
    }

    fn apply(&mut self, arg: CyclesLedgerCall) {
        match arg.arg {
            CyclesLedgerCallArg::Approve(ApproveArgs { from_subaccount, spender, amount, .. }) => {
                let from = Account { owner: arg.caller, subaccount: from_subaccount };
                let old_balance = self.balances.get(&from)
                    .unwrap_or_else(|| panic!("Account {} has 0 balance", from));
                self.balances.insert(from, old_balance - FEE);
                self.allowances.insert((from, spender), amount.0.to_u128().unwrap());
            },
            CyclesLedgerCallArg::Deposit { amount, arg: DepositArg { to, .. } } => {
                let old_balance = self.balances.get(&to).map(|b| *b).unwrap_or_default();
                self.balances.insert(to, old_balance + amount.0.to_u128().unwrap());
            },
            CyclesLedgerCallArg::Send(SendArgs { from_subaccount, amount, .. }) => {
                let from = Account { owner: arg.caller, subaccount: from_subaccount };
                let old_balance = self.balances.get(&from)
                    .unwrap_or_else(|| panic!("Account {} has 0 balance", from));
                self.balances.insert(from, old_balance - amount.0.to_u128().unwrap());
            },
            CyclesLedgerCallArg::Transfer(TransferArg { from_subaccount, to, amount, .. }) => {
                let from = Account { owner: arg.caller, subaccount: from_subaccount };
                let old_balance = self.balances.get(&from)
                    .unwrap_or_else(|| panic!("Account {} has 0 balance", from));
                let amount = amount.0.to_u128().unwrap();
                self.balances.insert(from, old_balance - amount - FEE);
                let old_balance = self.balances.get(&to).map(|b| *b).unwrap_or_default();
                self.balances.insert(to, old_balance + amount);
            },
            CyclesLedgerCallArg::TransferFrom(TransferFromArgs { spender_subaccount, from, to, amount, fee, memo, created_at_time  }) => {
                self.apply(CyclesLedgerCall {
                    caller: from.owner,
                    arg: CyclesLedgerCallArg::Transfer(TransferArg {
                        from_subaccount: from.subaccount,
                        to,
                        fee,
                        created_at_time,
                        memo,
                        amount: amount.clone(),
                    }),
                });
                let spender = Account { owner: arg.caller, subaccount: spender_subaccount };
                let allowance = self.allowances.get(&(from, spender))
                    .unwrap_or_else(||panic!("Allowance of {:?} is 0", (from, spender)));
                self.allowances.insert((from, spender), allowance - amount.0.to_u128().unwrap());
            },
        }
    }
}

// Represent a set of valid calls and the
// state that results from performing those
// calls on the state
#[derive(Clone, Debug, Default)]
pub struct CyclesLedgerCallsState {
    pub calls: Vec<CyclesLedgerCall>,
    pub state: CyclesLedgerState,
}

impl CyclesLedgerCallsState {
    fn apply(&mut self, arg: CyclesLedgerCall) {
        self.state.apply(arg.clone());
        self.calls.push(arg);
    }

    // Return the number of tokens available for minting
    fn token_pool(&self) -> u128 {
        self.state.token_pool()
    }

    fn accounts_with_at_least_fee(&self) -> Vec<(Account, u128)> {
        self.state.balances.iter().filter_map(|(account, balance)|
            if balance >= &FEE { Some((*account, *balance)) } else { None })
            .collect()
    }
}

fn arb_allowed_principal() -> impl Strategy<Value = Principal> {
    collection::vec(any::<u8>(), 0..30)
        .prop_filter_map("Management and anonimous principals are disabled", |bytes| {
            let principal = Principal::from_slice(&bytes);
            if principal == Principal::management_canister() ||
               principal == Principal::anonymous() {
                None
            } else {
                Some(principal)
            }
        })
}

fn arb_account() -> impl Strategy<Value = Account> {
    (arb_allowed_principal(), option::of(any::<[u8;32]>()))
        .prop_map(|(owner, subaccount)| Account { owner, subaccount })
}

fn arb_amount(max: u128) -> impl Strategy<Value = Nat> {
    (0..=max).prop_map(Nat::from)
}

fn arb_memo() -> impl Strategy<Value = Memo> {
    collection::vec(any::<u8>(), 0..32)
        .prop_map(|bytes| Memo(ByteBuf::from(bytes)))
}

fn arb_approve(token_pool: u128,
               allowances: Arc<HashMap<(Account, Account), u128>>,
               arb_approver: impl Strategy<Value = Account>)
               -> impl Strategy<Value = CyclesLedgerCall> {
    (arb_approver, arb_account(), arb_amount(token_pool))
        .prop_filter("self-approve disabled", |(approver, spender, _)| approver != spender )
        .prop_flat_map(
            move |(approver, spender, amount)| {
                let allowance = allowances.get(&(approver, spender)).map(|b| *b).unwrap_or_default();
                let arb_expected_allowance = option::of(Just(allowance.into()));
                let arb_suggested_fee = option::of(Just(FEE.into()));
                (option::of(arb_memo()), arb_expected_allowance, arb_suggested_fee).prop_map(
                    move |(memo, expected_allowance, fee)|
                        CyclesLedgerCall {
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
                            }.into()
                        }
                )
            }
    )
}

prop_compose! {
    fn arb_deposit(token_pool: u128, depositor: Principal)
                  (to in arb_account(),
                   amount in arb_amount(token_pool),
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
    fn arb_send(arb_from: impl Strategy<Value = (Account, u128)>)
               ((from, from_balance) in arb_from)
               (from in Just(from),
                to in arb_allowed_principal(),
                amount in (0..=from_balance).prop_map(Nat::from),
               )
               -> CyclesLedgerCall {
        let amount = Nat::from(amount);
        CyclesLedgerCall {
            caller: from.owner,
            arg: SendArgs {
                from_subaccount: from.subaccount,
                to,
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
                    amount in (0..=from_balance).prop_map(Nat::from),
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
                         amount in (0..=from_balance).prop_map(Nat::from),
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

pub fn arb_cycles_ledger_call_state(depositor: Principal, len: u8) -> impl Strategy<Value = CyclesLedgerCallsState> {
    fn step(state: CyclesLedgerCallsState, depositor: Principal, n: u8) -> impl Strategy<Value = CyclesLedgerCallsState> {
        if n == 0 {
            return Just(state).boxed();
        }

        let accounts = state.accounts_with_at_least_fee();
        let token_pool = state.token_pool();
        let allowances = Arc::new(state.state.allowances.clone());

        let mut arb_calls = vec![
            arb_deposit(token_pool, depositor).boxed()  
        ];
        if !accounts.is_empty() {
            let select_account_and_balance = Arc::new(select(accounts.clone()));

            // approve
            let select_account = select_account_and_balance.clone().prop_map(|(a, _)| a);
            let arb_approve = arb_approve(token_pool, allowances.clone(), select_account);
            arb_calls.push(arb_approve.boxed());

            // send
            let arb_send = arb_send(select_account_and_balance.clone());
            arb_calls.push(arb_send.boxed());

            // transfer
            let arb_transfer = arb_transfer(select_account_and_balance);
            arb_calls.push(arb_transfer.boxed());

            // transfer_from
            let accounts: HashMap<_, _> = accounts.iter().map(|a| a.clone()).collect();
            let mut from_spender_amount = vec![];
            for ((from, spender), allowance) in allowances.as_ref() {
                let Some(balance) = accounts.get(&from) else { continue; };
                from_spender_amount.push((*from, *spender, *allowance.min(balance)));
            }
            if !from_spender_amount.is_empty() {
                let arb_transfer_from = arb_transfer_from(select(from_spender_amount));
                arb_calls.push(arb_transfer_from.boxed());
            }
        }
        
        (Union::new(arb_calls), Just(state))
            .prop_flat_map(move |(call, mut state)| {
                state.apply(call);
                step(state, depositor, n - 1)
            }).boxed()
    }

    step(CyclesLedgerCallsState::default(), depositor, len)

}

#[test]
fn test() {
    proptest!(|(state in arb_cycles_ledger_call_state(Principal::anonymous(), 10))| {
        prop_assert_eq!(10, state.calls.len())
    })
}