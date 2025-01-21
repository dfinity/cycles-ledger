## Cycles Ledger API

The canister ID of the cycles ledger is [`um5iw-rqaaa-aaaaq-qaaba-cai`](https://dashboard.internetcomputer.org/canister/um5iw-rqaaa-aaaaq-qaaba-cai).

The cycles ledger complies with the [ICRC-1](https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-1/README.md),
[ICRC-2](https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-2/README.md), and [ICRC-3](https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-3/README.md) standards and therefore offers all the corresponding endpoints.

The additional endpoints are presented in the following.

### `deposit`
```
type Account = record { owner : principal; subaccount : opt vec nat8 };

type BlockIndex = nat;

type DepositArgs = record {
  to : Account;
  memo : opt vec nat8;
};

type DepositResult = record { balance : nat; block_index : BlockIndex };

deposit : (DepositArgs) -> (DepositResult);
```

This endpoint increments the balance of the provided account by the number of attached cycles. There is no fee when depositing cycles but at least 100M cycles must be attached, otherwise the call is rejected. 
The sender can optionally provide a memo as well. The memo may be at most 32 bytes long.

### `withdraw`
```
type WithdrawArgs = record {
  amount : nat;
  from_subaccount : opt vec nat8;
  to : principal;
  created_at_time : opt nat64;
};

type RejectionCode = variant {
  NoError;
  CanisterError;
  SysTransient;
  DestinationInvalid;
  Unknown;
  SysFatal;
  CanisterReject;
};

type WithdrawError = variant {
  GenericError : record { message : text; error_code : nat };
  TemporarilyUnavailable;
  FailedToWithdraw : record {
    fee_block : opt nat;
    rejection_code : RejectionCode;
    rejection_reason : text;
  };

withdraw : (WithdrawArgs) -> (variant { Ok : BlockIndex; Err : WithdrawError });
```

This endpoint withdraws the given amount from the caller's account and transfers the cycles to the provided canister ID.
In addition to the amount and the canister ID (parameter `to`), the caller can provide a subaccount and a `created_at_time` timestamp. The timestamp is used to deduplicate calls, i.e., funds are withdrawn (at most) once when calling the endpoint multiple times with the same parameters.

A fee of 100M cycles is deducted when withdrawing cycles. 

### `withdraw_from`
```
type WithdrawFromArgs = record {
  spender_subaccount : opt vec nat8;
  from : Account;
  to : principal;
  amount : nat;
  created_at_time : opt nat64;
};

withdraw_from : (WithdrawFromArgs) -> (variant { Ok : BlockIndex; Err : WithdrawFromError });
```
This endpoint is similar to `withdraw` in that cycles are sent to the target canister (parameter `to`) if the call is successful. The difference is that the caller can specify any account (parameter `from`) from which the cycles are deducted.
The owner of this account must have issued an `icrc2_approve` call beforehand, authorizing access to the funds for the caller's account, composed of the caller's principal and, optionally, a specific subaccount (parameter `spender_subaccount`).

A fee of 100M cycles is deducted when withdrawing cycles. 

### `create_canister`
```
type CanisterSettings = record {
  controllers : opt vec principal;
  compute_allocation : opt nat;
  memory_allocation : opt nat;
  freezing_threshold : opt nat;
  reserved_cycles_limit : opt nat;
};

type SubnetFilter = record {
  subnet_type : opt text;
};

type SubnetSelection = variant {
  Subnet : record {
    subnet : principal;
  };
  Filter : SubnetFilter;
};

type CmcCreateCanisterArgs = record {
  settings : opt CanisterSettings;
  subnet_selection : opt SubnetSelection;
};

type CreateCanisterArgs = record {
  from_subaccount : opt vec nat8;
  created_at_time : opt nat64;
  amount : nat;
  creation_args : opt CmcCreateCanisterArgs;
};

type CreateCanisterSuccess = record {
  block_id : BlockIndex;
  canister_id : principal;
};

type CreateCanisterError = variant {
  InsufficientFunds : record { balance : nat };
  TooOld;
  CreatedInFuture : record { ledger_time : nat64 };
  TemporarilyUnavailable;
  Duplicate : record {
    duplicate_of : nat;
    canister_id : opt principal;
  };
  FailedToCreate : record {
    fee_block : opt BlockIndex;
    refund_block : opt BlockIndex;
    error : text;
  };
  GenericError : record { message : text; error_code : nat };
};

create_canister : (CreateCanisterArgs) -> (variant { Ok : CreateCanisterSuccess; Err : CreateCanisterError });
```

This endpoint instructs the cycles ledger to create a canister, deducting the required cycles from the caller's account.
The caller must specify the number of cycles to be used for the creation of the canister. In addition to the specified amount, a fee of 100M cycles is deducted.
A `created_at_time` timestamp can be provided to ensure that (at most) one canister is created when calling the endpoint multiple times with the same parameters.
The caller can specify the desired [canister settings](https://internetcomputer.org/docs/current/developer-docs/smart-contracts/maintain/settings). If no settings are provided, the standard settings are used.
Moreover, the caller can influence where the canister will be deployed by selecting a specific subnet or by providing a [subnet type](https://internetcomputer.org/docs/current/references/subnets/subnet-types/).

### `create_canister_from`
```
type CreateCanisterFromArgs = record {
  from : Account;
  spender_subaccount : opt vec nat8;
  created_at_time : opt nat64;
  amount : nat;
  creation_args : opt CmcCreateCanisterArgs;
};

create_canister_from : (CreateCanisterFromArgs) -> (variant { Ok : CreateCanisterSuccess; Err : CreateCanisterFromError });
```

This endpoint creates a new canister the same way as the `create_canister` endpoint, the difference being the source of the cycles spent to create the canister.
The call specifies the account (parameter `from`) from which the cycles are deducted. Note that there is again a fee of 100M added to the specified amount.
The owner of this account must have issued an `icrc2_approve` call beforehand, authorizing access to the funds for the caller's account, composed of the caller's principal and, optionally, a specific subaccount (parameter `spender_subaccount`).

