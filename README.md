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