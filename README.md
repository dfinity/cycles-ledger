# Cycles Ledger

The cycles ledger is a global ledger canister that enables principal IDs to hold cycles.

The cycles ledger complies with the [ICRC-2](https://github.com/dfinity/ICRC-1/blob/main/standards/ICRC-2/README.md) and [ICRC-1](https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-1/README.md) token standards.
Additionally, it implements the endpoints defined in the proposed [ICRC-3](https://github.com/dfinity/ICRC-1/pull/128) standard.

The cycles ledger further provides endpoints to deposit and send out cycles, and also
to create canisters using cycles. These custom endpoints are introduced in the following.

## Depositing Cycles

The cycles ledger has the following endpoint for other canisters to deposit cycles.

```
type DepositArgs = record {
  to : Account;
  memo : opt vec nat8;
};

type DepositResult = record { balance : nat; block_index : nat };

deposit : (DepositArgs) -> (DepositResult);
```

When invoked with a particular account (and, optionally, a memo), the balance of the account is incremented by the number of cycles attached to the call. There is no fee when depositing cycles; however, the number of cycles must be at least the transfer fee of **100M cycles**.

> NOTE: The deposit is rejected if fewer than 100M cycles are attached to the call.

## Sending Cycles

The cycles ledger has the following endpoint to send cycles to other canisters.

```
type BlockIndex = nat;

type RejectionCode = variant {
  NoError;
  CanisterError;
  SysTransient;
  DestinationInvalid;
  Unknown;
  SysFatal;
  CanisterReject;
};

type SendArgs = record {
    amount : nat;
    from_subaccount : opt vec nat8;
    to : principal;
    created_at_time : opt nat64;
};

type SendError = variant {
  GenericError : record { message : text; error_code : nat };
  TemporarilyUnavailable;
  FailedToSend : record {
    fee_block : opt nat;
    rejection_code : RejectionCode;
    rejection_reason : text;
  };
  Duplicate : record { duplicate_of : nat };
  BadFee : record { expected_fee : nat };
  InvalidReceiver : record { receiver : principal };
  CreatedInFuture : record { ledger_time : nat64 };
  TooOld;
  InsufficientFunds : record { balance : nat };
};

send : (SendArgs) -> (variant { Ok : BlockIndex; Err : SendError });
```

The two required parameters are the amount to be sent and the principal ID of
the targeted canister ID. Optionally, the subaccount from which cycles are
deducted and the time at which the transaction is created can be set as well.

There is a fee of **100M cycles** for sending cycles to another canister.

> NOTE: The function returns an error when the parameter `to` is not a valid canister ID.

## Creating Canisters Using Cycles

The canister creation process via cycles can be triggered from the cycles ledger
using the endpoint `create_canister`.

```
type CreateCanisterArgs = record {
  from_subaccount : opt vec nat8;
  created_at_time : opt nat64;
  amount : nat;
  creation_args : opt CmcCreateCanisterArgs;
};

type CmcCreateCanisterArgs = record {
  settings : opt CanisterSettings;
  subnet_selection : opt SubnetSelection;
};

type CanisterSettings = record {
  controllers : opt vec principal;
  compute_allocation : opt nat;
  memory_allocation : opt nat;
  freezing_threshold : opt nat;
};

type SubnetFilter = record {
  subnet_type : opt text;
};

type SubnetSelection = variant {
  /// Choose a specific subnet
  Subnet : record {
    subnet : principal;
  };
  Filter : SubnetFilter;
};

type CreateCanisterError = variant {
  InsufficientFunds : record { balance : nat };
  TooOld;
  CreatedInFuture : record { ledger_time : nat64 };
  TemporarilyUnavailable;
  Duplicate : record { duplicate_of : nat };
  FailedToCreate : record {
    fee_block : opt BlockIndex;
    refund_block : opt BlockIndex;
    error : text;
  };
  GenericError : record { message : text; error_code : nat };
};

create_canister : (CreateCanisterArgs) -> (variant { Ok : CreateCanisterSuccess; Err : CreateCanisterError });
```

The only parameter that must be provided is the number of cycles that should
be used for the canister creation.
The cycles ledger fee of **100M** cycles is deducted from the user's account
together with the specified `amount`. The cycles ledger then sends the request to create a canister
to the cycles minting canister, attaching `amount` cycles to the call.
The cost for the canister creation itself can be found
[here](https://internetcomputer.org/docs/current/developer-docs/gas-cost).

> NOTE: The canister is created on a **random subnet** unless specified otherwise. `SubnetSelection`
can be used to specify a particular subnet or subnet type.

## Make a new Release

The CI job [release-with-github.yml](https://github.com/dfinity/cycles-ledger/actions/workflows/release-with-github.yml) is responsible to create a new release. The release job uses [cargo-release](https://github.com/crate-ci/cargo-release/blob/master/docs/reference.md). This project follows [Semantic Versioning 2.0.0](https://semver.org/) (aka semver).

The release job can be triggered by using [`gh`](https://cli.github.com/) or [directly from github](https://github.com/dfinity/cycles-ledger/actions/workflows/release-with-github.yml):

```
gh workflow run --repo dfinity/cycles-ledger "release-with-github.yml" -f semverBump=(major|minor|patch)
```

The job will then bump the version based on the strategy passed via `semverBump`, make the release and make a PR with the version changes and the release linked to the PR. See [this](https://github.com/crate-ci/cargo-release/blob/master/docs/reference.md#bump-level) for valid `semverBump` values and their effect.
