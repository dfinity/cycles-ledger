# Cycles Ledger

The cycles ledger is a global ledger canister that enables principal IDs to hold cycles.

The cycles ledger complies with the [ICRC-1 token standard](https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-1).
In addition to the ICRC-1 functionality, the cycles ledger provides endpoints to deposit and send out cycles, and also
to create canisters using cycles. These custom endpoints are introduced in the following.

## Depositing Cycles

The cycles ledger has the following endpoint for other canisters to deposit cycles.

```
deposit : (record { to : Account; memo : opt blob }) -> (record { txid : nat; balance : nat });
```

When invoked with a particular account (and, optionally, a memo), the balance of the account is incremented by the
number of cycles attached to the call. There is no fee when depositing cycles; however, the number of cycles
must be at least the transfer fee of **100M cycles**.

> NOTE: The deposit is rejected if fewer than 100M cycles are attached to the call.

 


## Sending Cycles

TO DO

## Creating Canisters Using Cycles

TO DO


## Make a new Release

The CI job [release-with-github.yml](https://github.com/dfinity/cycles-ledger/actions/workflows/release-with-github.yml) is responsible to create a new release. The release job uses [cargo-release](https://github.com/crate-ci/cargo-release/blob/master/docs/reference.md). This project follows [Semantic Versioning 2.0.0](https://semver.org/) (aka semver).

The release job can be triggered by using [`gh`](https://cli.github.com/) or [directly from github](https://github.com/dfinity/cycles-ledger/actions/workflows/release-with-github.yml):

```
gh workflow run --repo dfinity/cycles-ledger "release-with-github.yml" -f semverBump=(major|minor|patch)
```

The job will then bump the version based on the strategy passed via `semverBump`, make the release and make a PR with the version changes and the release linked to the PR. See [this](https://github.com/crate-ci/cargo-release/blob/master/docs/reference.md#bump-level) for valid `semverBump` values and their effect.
