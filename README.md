# vega-custody-sdk

![vega-custody-sdk](assets/tile.svg)

Chain of record to custody.

> **Licensing.** Source-available, not open source. Free for personal use; free for registered small businesses (under US$1M revenue and valuation); everyone else needs a commercial license (see LICENSE; for a commercial license write to jasonblasiak.ai.mail@gmail.com). Patent pending. Draft licence text, not yet reviewed by an attorney.

Package: `vega_custody` (src layout). Depends on: none.

## Modules

| Module | What it does |
|---|---|
| `capsule` | Wraps every prompt, action and response: data, metadata, timestamp, predecessor hash, own hash. |
| `dag` | Append-only record of what happened and a second chain of where it is stored. Written to every replica and read back, or refused. |
| `ledger` | Ledger-agnostic mint: hash-chained file locally and on an external drive, Merkle-batched anchors for an optional public witness. Hashes only. |
| `store` | Three-source write gate (local, external, server): a save lands on all three or on none, and every save is scored and recorded. |

## What it does NOT do (read this)

- It records and checks; it does not decide what is allowed (that is the governance jacket).
- A hash chain proves order and tamper evidence, not that the recorded content is true.
- An external drive and a server are only as safe as their operators.

## Status

See STATUS.md. Tests: 108 tests in 9 files, all passing.  See SECURITY.md for the threat model.

## Run the tests

Put `src` of this repo and of the repos it depends on on PYTHONPATH, then run each file in `tests/`.
