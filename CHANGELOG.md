<!-- next-header -->

# CHANGELOG

## [Unreleased] - ReleaseDate
* Add support for `initial_balances` in `InitArgs`. When specifying initial balances it is up to the installer to ensure that the cycles ledger has sufficient cycles available to spend these cycles.
* Allow the anonymous principal to receive, approve, and transfer tokens.

* Added support for [ICRC-106](https://github.com/dfinity/ICRC-1/blob/7f9b4739d9b3ec2cf549bf468e3a1731c31eecbf/standards/ICRC-106/ICRC-106.md)

## [1.0.5] - 2025-06-24
* Add support for [ICRC-103](https://github.com/dfinity/ICRC/blob/main/ICRCs/ICRC-103/ICRC-103.md).

## [1.0.4] - 2025-04-10
* Fixed a bug where refund blocks after an unsuccessful `withdraw` or `create_canister` had the timestamp of the initial burn block instead of the time when the error was processed. Approvals that have expired in the meantime will not be refunded.

## [1.0.3] - 2024-11-18
* Adapted `icrc3_get_tip_certificate` to be compliant with the ICRC-3 specification by changing the encoding of `last_block_index` to `leb128`.

## [1.0.2] - 2024-10-28
* Added `get_icp_xdr_conversion_rate` to mock CMC

No changes to the cycles ledger. Released because a community project relies on the mock CMC and would like to have this feature available.

## [1.0.1] - 2024-08-22
* Update `ic-cdk` dependency to patch a security issue.

## [1.0.0] - 2024-06-18
* Added the logo to the metadata value `icrc1:logo`.
* Fixed a bug where the cycles ledger took control over a newly created canister if `creation_args` is `Some` and `canister_settings` is `None`.

## [0.6.0] - 2024-03-25

## [0.5.0] - 2024-03-21

## [0.4.0] - 2024-03-20

## [0.3.0] - 2024-02-09

## [0.2.8] - 2024-01-19

## [0.2.1] - 2023-09-20

## [0.2.0] - 2023-09-18

## [0.1.0] - 2023-07-12

<!-- next-url -->
[Unreleased]: https://github.com/dfinity/cycles-ledger/compare/cycles-ledger-v1.0.5...HEAD
[1.0.4]: https://github.com/dfinity/cycles-ledger/compare/cycles-ledger-v1.0.4...cycles-ledger-v1.0.5
[1.0.4]: https://github.com/dfinity/cycles-ledger/compare/cycles-ledger-v1.0.3...cycles-ledger-v1.0.4
[1.0.3]: https://github.com/dfinity/cycles-ledger/compare/cycles-ledger-v1.0.2...cycles-ledger-v1.0.3
[1.0.2]: https://github.com/dfinity/cycles-ledger/compare/cycles-ledger-v1.0.1...cycles-ledger-v1.0.2
[1.0.1]: https://github.com/dfinity/cycles-ledger/compare/cycles-ledger-v1.0.0...cycles-ledger-v1.0.1
[1.0.0]: https://github.com/dfinity/cycles-ledger/compare/cycles-ledger-v0.6.0...cycles-ledger-v1.0.0
[0.6.0]: https://github.com/dfinity/cycles-ledger/compare/cycles-ledger-v0.5.0...cycles-ledger-v0.6.0
[0.5.0]: https://github.com/dfinity/cycles-ledger/compare/cycles-ledger-v0.4.0...cycles-ledger-v0.5.0
[0.4.0]: https://github.com/dfinity/cycles-ledger/compare/cycles-ledger-v0.3.0...cycles-ledger-v0.4.0
[0.3.0]: https://github.com/dfinity/cycles-ledger/compare/cycles-ledger-v0.2.8...cycles-ledger-v0.3.0
[0.2.8]: https://github.com/dfinity/cycles-ledger/compare/cycles-ledger-v0.2.1...cycles-ledger-v0.2.8
[0.2.1]: https://github.com/dfinity/cycles-ledger/compare/cycles-ledger-v0.2.0...cycles-ledger-v0.2.1
[0.2.0]: https://github.com/dfinity/cycles-ledger/compare/cycles-ledger-v0.2.0...cycles-ledger-v0.2.0

