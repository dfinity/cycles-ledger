# Proposal to upgrade the cycles ledger canister

Repository: `https://github.com/dfinity/cycles-ledger.git`

Git hash: `58f1d01ce1e5e41e61005f8103cc7560e9d81cc2`

New compressed Wasm hash: `70f8bd40d022374622b34266d2c182d2a5b711d965f3bef9e505467a84c40bce`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `um5iw-rqaaa-aaaaq-qaaba-cai`

Previous cycles ledger proposal: https://dashboard.internetcomputer.org/proposal/138595

Forum discussion: https://forum.dfinity.org/t/nns-updates-aggregation-thread/23551

---

## Motivation

This proposal upgrades the cycles ledger to version 1.1.0, which fixes several bugs and adds support for new canister settings and ICRC-10.

The main reasons for the upgrade are the following fixes:

* **Stricter decoding of call arguments.** The `candid` library is upgraded to 0.10.40, which fixes the decoding of subaccounts in call arguments.
* **Allowance refunds of failed delegated calls.** The handling of allowance refunds after a failed `withdraw_from` or `create_canister_from` call is improved so that it takes changes to the allowance made by the owner into account.
* **Pruning of expired transactions.** The work spent pruning expired deduplication entries in a single message is now bounded.
* **Correct error precedence.** `icrc1_transfer`, `icrc2_approve`, and `icrc2_transfer_from` now return `BadFee` instead of `InsufficientFunds` when both apply.

In addition, the upgrade:

* lets `create_canister` and `create_canister_from` set the canister settings `wasm_memory_limit`, `wasm_memory_threshold`, `log_visibility`, and `environment_variables` on the new canister,
* adds support for ICRC-10 (`icrc10_supported_standards`) and returns the canonical document URLs for ICRC-103 and ICRC-106 in `icrc1_supported_standards`,
* updates `ic-cdk` to 0.19 and the Rust toolchain to 1.91.1.


## Release Notes

```
git log --format='%C(auto) %h %s' 29d98de5131918649a4c1cdd47fc176dea8770ef..58f1d01ce1e5e41e61005f8103cc7560e9d81cc2 --
58f1d01 chore(release): cycles-ledger-v1.1.0 (#188)
6669941 chore: add missing changelog entries and bump candid to 0.10.40 before releasing 1.1.0 (#186)
1e72b31 fix: bound the instructions spent pruning expired transactions (#184)
4f12dc4 chore: Add IntelliJ IDEA directory to .gitignore (#157)
f3517ce chore(deps): bump rustls from 0.23.35 to 0.23.46 (#185)
2faa00a chore: Move actions substitutions to `env:` for hardening (#183)
b1ea7da fix: do not reimburse an allowance the owner changed during a failed call (#182)
2703d36 chore(deps): bump quinn-proto from 0.11.14 to 0.11.17 (#181)
f921070 chore(deps): bump bytes from 1.11.0 to 1.12.1 (#169)
ea22d61 chore(deps): bump time from 0.3.44 to 0.3.55 (#170)
e54dca8 chore(deps): bump quinn-proto from 0.11.13 to 0.11.14 (#171)
3deed54 chore(deps): bump rustls-webpki from 0.103.8 to 0.103.14 (#177)
f44ee39 fix: align test_supported_standards expectations with canonical URLs (#180)
13858dc chore(deps): bump rand from 0.8.5 to 0.8.6 (#176)
7429361 fix: DEFI-2824: Use canonical ICRC-103 and ICRC-106 document URLs (#179)
ddc0bbf feat: DEFI-1902: Add support for ICRC-10 (#178)
301bae3 chore: pin GitHub Actions to commit SHAs (#174)
933e368 fix: check fee before funds (#173)
9431bd0 chore: update dependencies to allow new canister settings (#168)
dbebe79 test: FI-1857: Test upgrade and reinstall with index that handles burn and mint fees (#167)
 ```

## Upgrade args

```
git fetch
git checkout 58f1d01ce1e5e41e61005f8103cc7560e9d81cc2
didc encode '()' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 58f1d01ce1e5e41e61005f8103cc7560e9d81cc2
"./scripts/docker-build"
sha256sum ./cycles-ledger.wasm.gz
```
