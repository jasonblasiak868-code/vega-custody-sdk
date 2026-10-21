# vega-custody-sdk — Specification

Spec v1.0 — 2026-10-19 — describes the published reference implementation as tested; where this document and the source disagree, the source wins.

## 1. Purpose and scope

This specification covers the reference implementation in `src/vega_custody/` as tested by the 114 tests in 10 files under `tests/`. It specifies:

- **Capsule** — the turn record format, hashing, verification, and chain verification
- **DAG** — the append-only content chain and location chain (what happened, where it lives)
- **Ledger** — the ledger-agnostic mint, verification, Merkle batching, and public witness interface
- **Store** — the three-source write gate with scoring, audit, and load
- **Proc** — bounded process execution with verified kill (helper used by the family)
- **Safe paths** — filesystem safety rules (helper used by the family)

Out of scope: public-chain anchoring backends beyond the built local, drive, and timestamp backends (these are interfaces only per STATUS.md); OS-level sandboxing; cryptographic review; policy decisions about what actions are allowed.

## 2. Vocabulary

| Term | Definition (from code) |
|---|---|
| **Capsule** | A JSON object wrapping one turn: data (base64), metadata, timestamp, predecessor hash, prefix hash (digest over all preceding fields). Created by `capsule.make()`, verified by `capsule.verify()`. |
| **Prefix hash** | SHA-256 of the canonical capsule excluding the `prefix_hash` field itself. Links capsules in a chain. |
| **Predecessor** | The `prefix_hash` of the previous capsule in a sequence (or `GENESIS` = 64 zeros for the first). |
| **Chain / DAG** | An append-only sequence of entries, each carrying `entry_hash` (hash of all fields except `entry_hash`), `seq` (0-based index), `parents` (list of parent `entry_hash` values). A DAG allows multiple parents per entry. |
| **Entry hash** | SHA-256 of the canonical entry excluding `entry_hash`. |
| **Record-or-refuse** | A write succeeds only when written to every configured replica and read back identically; any failure rolls back all replicas and raises. |
| **Fail closed** | On any inconsistency (tamper, replica disagreement, missing parent, credential scan hit), the chain/ledger refuses to open or extend. |
| **Content DAG** | The chain recording what happened (`kind`, `payload`, `parents`). |
| **Location DAG** | The chain recording where content lives (`LOCATION` entries with `content_entry`, `location_class`, `uri`, `readback_sha256`). |
| **Location class** | One of `local`, `external`, `server` — the three physical source categories. |
| **Read-back verification** | A location entry is only recorded if the bytes at the URI hash to the same `data_sha256` as the content entry. |
| **Ledger / Mint** | A hash-chained record of commitments. `mint(commitment)` records a `MINT` entry with the commitment's leaf hash and the commitment metadata. Single-use: a leaf cannot be minted twice. |
| **Commitment** | A dict with allow-listed metadata fields only (`kind`, `device`, `surface`, `action`, `action_hash`, `expiry`, `nonce_sha256`, `nonce`, `signature`). No parameters. |
| **Leaf** | SHA-256 of the canonical commitment. The mint stores the leaf, not the full commitment. |
| **WCOMMIT** | A commitment `kind` that requires a human signature check (via `commitment_check` callback) before minting. |
| **ReadOnlyLedger** | A view exposing only `verify()` and `inclusion_proof()` — no `mint`, no `anchor`, no chain handle. Handed to gates and contained code. |
| **Merkle root / proof** | Domain-separated (leaf `0x00`, node `0x01`) tree over commitment leaves. Odd nodes carried up unchanged. `inclusion_proof(commitment)` returns the path to the anchoring root. |
| **Witness** | An optional backend that receives only the Merkle root (32 bytes). Built: `FileWitness` (local file), `OpenTimestampsWitness` (HTTPS calendar, unverified live). |
| **Three-source store** | A save writes to `local`, `external`, `server` backends. Only succeeds if all three hold the exact bytes (read back), the capsule verifies, the save is scored, and both DAGs record it. |
| **Score** | A provenance-completeness floor (0..1) from a scorer function. Default checks: `has_source`, `has_license_class`, `has_data`, `has_timestamp`, `has_lineage`. A save with no valid score is refused. |
| **Bounded process** | `proc.run_bounded(argv, stdin, timeout, cap)` reads output in chunks, caps at `cap+1` bytes/stream, kills the whole process tree on timeout/overflow, and verifies the kill. |
| **ProcessJob** | Windows job object / POSIX process group wrapper that keeps a program and all descendants inside one kernel object (Windows) or process group (POSIX). |

## 3. Components

### 3.1 `vega_custody.capsule.capsule`

**Role:** Wrap every prompt, action, and response in a tamper-evident turn record that chains to its predecessor.

**Public interface:**
- `make(data, metadata=None, predecessor=None, timestamp=None) -> dict`
- `verify(c: dict) -> bool` (raises `CapsuleError` on failure)
- `verify_chain(capsules) -> bool` (raises `CapsuleError` on failure)
- `data_of(c: dict) -> str | bytes`
- `to_bytes(c: dict) -> bytes`
- `from_bytes(b: bytes) -> dict` (verifies then returns)

**Behavior:**
- `make` canonicalizes metadata (sorted keys, no NaN), base64-encodes data, computes `data_sha256`, sets `epoch`/`utc`, sets `predecessor` (or `GENESIS`), computes `prefix_hash`. Refuses: non-str/bytes data, forbidden metadata field names (`key`, `secret`, `passphrase`, `password`, `private_key`, `privkey`, `token`, `seed`, `api_key`), credential-shaped values in metadata (regex for API keys, JWTs, private keys, etc.).
- `verify` checks all required fields present, version matches, canonical JSON, base64 valid, data_type valid, `data_sha256` matches decoded data, `prefix_hash` matches recomputed hash. Raises `CapsuleError` on any mismatch.
- `verify_chain` verifies each capsule and that each `predecessor` equals the previous capsule's `prefix_hash`.

**Invariants:**
- A capsule's `prefix_hash` is a digest over everything except itself — any field change is detected.
- Chain order is enforced by `predecessor` linkage; reordering is caught.
- Metadata never carries key material (enforced at make and verify).
- Data is opaque bytes; `data_type` distinguishes text vs bytes for round-trip.

### 3.2 `vega_custody.dag.dag` — `Chain` and `Dag`

**Role:** `Chain` is one append-only hash-linked ledger replicated to multiple paths. `Dag` pairs a content `Chain` and a location `Chain` (via `LocationChain`).

**Public interface (`Chain`):**
- `__init__(paths: list[Path])` — loads all replicas, verifies byte-identity and internal consistency, raises `ChainBroken` on any mismatch.
- `__len__()`, `head()`, `has(entry_hash)`, `get(entry_hash)`, `entries()`, `read_primary()`
- `verify(expected_head=None, min_length=None) -> (bool, list[str])` — re-reads all replicas off disk; optional external head/length checks for truncation detection.
- `record(kind: str, payload: dict, parents=None) -> dict` — appends an entry to every replica atomically (record-or-refuse), returns the entry.

**Public interface (`Dag`):**
- `__init__(content_paths, location_paths)`
- `record(kind, payload, parents=None) -> dict` — delegates to content chain.
- `record_location(content_entry_hash, location_class, uri, readback_sha256, **extra) -> dict` — records a `LOCATION` entry in location chain; verifies content entry exists, `readback_sha256` matches content's `data_sha256`.
- `record_stage(stage: str, digest: str, parents=None, **extra) -> dict` — records a sealing stage (digest only, e.g., `STAGE:aes-gcm`).
- `verify() -> (bool, list[str])` — verifies both chains.

**Behavior:**
- `record`: validates `kind`, `payload` is a JSON object, no forbidden field names (normalized: `privatekey`, `accesstoken`, etc.), no credential-shaped values in payload, all parents exist (if non-genesis). Creates entry with `seq`, `kind`, `payload`, `parents`, `epoch`, `utc`, `entry_hash`. Appends to every replica under cross-process lock (`_FileLock`), reads back each write to confirm byte-identity. On any failure, rolls back all touched replicas and raises `RecordRefused`.
- `verify`: re-reads every replica from disk; checks internal consistency, replica agreement, optional `expected_head` (truncation detection), optional `min_length`.

**Invariants:**
- **Append-only**: no truncation, no edits. Tampering detected on `verify` and on reopen (`ChainBroken`).
- **Replica agreement**: all paths must be byte-identical at all times; a diverging replica refuses to open.
- **Record-or-refuse**: partial writes are rolled back; the chain is never left in a half-written state.
- **DAG parents**: every non-genesis entry must name at least one parent; all parents must already exist.
- **Hashes only**: payloads may not carry key material (field names or credential-shaped values).
- **Fail closed**: any inconsistency → `ChainBroken` on open, `RecordRefused` on write.

### 3.3 `vega_custody.dag.locations` — `LocationChain`

**Role:** The second chain — where each saved thing physically lives. Every location entry points back at a content entry and carries a digest read back from that location.

**Public interface:**
- `record_location(content_entry_hash, location_class, uri, readback_sha256, **extra) -> dict`
- `where(content_entry_hash) -> list[dict]`

**Behavior:**
- `location_class` must be one of `local`, `external`, `server`.
- Content entry must exist in the content DAG.
- Content entry must carry `data_sha256` in its payload.
- `readback_sha256` must equal that `data_sha256` — a location that does not hold the exact bytes cannot be recorded.

**Invariants:**
- A location entry is bound to a real content entry.
- Read-back verification is mandatory — no "trust but verify," only verify.

### 3.4 `vega_custody.ledger.ledger` — `Ledger` and `ReadOnlyLedger`

**Role:** Ledger-agnostic mint + verify. Replicates a hash-chained file to every configured backend (local, drive). Optional public witness anchors Merkle roots of batches.

**Public interface (`Ledger`):**
- `__init__(backends, witness=None, batch_size=64, commitment_check=None)` — opens a `Chain` over backend paths; required backends must be available; optional backends mark `degraded` if unavailable.
- `mint(commitment: dict) -> dict` — records a `MINT` entry with `leaf` and `commitment`. Returns receipt with `leaf`, `entry`, `seq`, `replicas`, `degraded`, optional `anchor`/`anchor_error`.
- `reader() -> ReadOnlyLedger`
- `verify(commitment: dict) -> bool` — re-verifies whole chain, checks commitment leaf exists in a `MINT` entry, re-checks WCOMMIT signature if `commitment_check` configured.
- `anchor_pending() -> dict` — batches pending `MINT` entries since last anchor, computes Merkle root, calls `witness.anchor(root_hex)`, records `ANCHOR` entry.
- `inclusion_proof(commitment: dict) -> dict | None` — Merkle path from commitment to its anchor batch root.

**Public interface (`ReadOnlyLedger`):**
- `verify(commitment) -> bool`
- `inclusion_proof(commitment) -> dict | None`

**Behavior:**
- `mint`: validates commitment fields against `META_FIELDS` allow-list, required fields present (`action`, `action_hash`, `expiry`, `nonce_sha256`). If `commitment_check` given and `kind == "WCOMMIT"`, signature must verify (fail closed). Leaf must not already exist (single-use). Records `MINT` entry. If witness configured and batch full, attempts anchor (mint stands even if anchor fails).
- `verify`: returns `False` (never raises) on any failure — chain broken, commitment not found, WCOMMIT signature invalid.
- `ReadOnlyLedger` is a frozen view with no `mint`, `anchor`, or chain access. Gates and contained code receive this, not the full `Ledger`.

**Invariants:**
- **Single-use**: a leaf (commitment hash) can be minted once.
- **Metadata only**: commitments carry only allow-listed metadata; parameters are refused.
- **Fail closed verify**: any chain inconsistency → `False`.
- **Authority separation**: only the commit step (which checked a human signature) holds `mint`; gates get `reader()`.

### 3.5 `vega_custody.ledger.merkle`

**Role:** Domain-separated Merkle tree for batching commitment leaves into one root.

**Public interface:**
- `root(leaves: list[bytes]) -> bytes`
- `proof(leaves: list[bytes], index: int) -> list[tuple[str, bytes]]` — `('L'|'R', sibling_hash)` from leaf to root.
- `verify_proof(leaf: bytes, path, expected_root: bytes) -> bool`

**Behavior:**
- Leaf hash: `SHA256(0x00 || leaf)`
- Node hash: `SHA256(0x01 || left || right)`
- Odd node carried up unchanged (never duplicated).

**Invariants:**
- Second-preimage resistance: an internal node cannot pass as a leaf (verified in `redteam_2_ledger_and_store.py`).

### 3.6 `vega_custody.ledger.backend_local` — `LocalBackend`

**Role:** The always-on record on this machine.

**Public interface:**
- `check()` — ensures parent directory exists.

### 3.7 `vega_custody.ledger.backend_drive` — `DriveBackend`

**Role:** The same record on a USB/external drive. Fails if the drive is not mounted (prevents silent writes to system disk).

**Public interface:**
- `check()` — verifies `mount_point` is a directory and (if `verify_mount=True`) a real mount point via `os.path.ismount`. Refuses `/` as mount anchor on POSIX.

### 3.8 `vega_custody.ledger.backend_timestamp` — `FileWitness`, `OpenTimestampsWitness`

**Role:** Public witnesses — only a 32-byte Merkle root ever leaves the machine.

**Public interface:**
- `FileWitness.anchor(root_hex) -> dict` — appends JSON line to local file.
- `OpenTimestampsWitness.anchor(root_hex) -> dict` — POSTs root to calendar URL (HTTPS only, or HTTP for loopback test). No redirects followed. Receipt size-capped (1 MB). Returns `{"witness": "opentimestamps", "status": "pending", "receipt_b64": ...}`.

**Behavior:**
- URL validation: must be HTTPS (or HTTP for 127.0.0.1/localhost/::1), hostname required.
- Root validation: exactly 64 lowercase hex chars.
- `_NoRedirect` handler prevents redirect chains from carrying the root to another host.

**Invariants:**
- Only the root leaves the machine; no commitment content, no metadata.
- Unverified live — treat as unverified until you have a stored receipt and have upgraded/verified it with the reference `ots` client.

### 3.9 `vega_custody.store.store` — `DirBackend`, `ThreeSourceStore`

**Role:** `DirBackend` is a directory source (local folder, mounted drive, synced server path). `ThreeSourceStore` is the write gate: a save succeeds only when ALL THREE sources hold the exact bytes, read back, the save is scored, and both DAGs record it.

**Public interface (`DirBackend`):**
- `put(key, data: bytes)` — atomic write via `.tmp` + `os.replace`
- `get(key) -> bytes | None`
- `delete(key)`
- `uri(key) -> str`

**Public interface (`ThreeSourceStore`):**
- `__init__(backends: dict, dag, scorer=default_score, min_score=0.0)` — `backends` must have exactly keys `local`, `external`, `server`. Roots must be distinct and non-nested (three copies in one place are one copy).
- `save(c: dict) -> dict` — verifies capsule, computes digest, scores, writes to all three backends (read-back verified), records `SAVE` in content DAG, records `LOCATION` in location DAG for each source. On any failure: rolls back written files, records `SAVE_ABORTED` in DAG, raises `StoreRefused`.
- `audit(digest: str) -> dict` — returns per-source status: `ok` / `missing` / `corrupt` / `unavailable`.
- `load(digest: str) -> dict` — returns capsule from first source whose bytes verify.

**Behavior:**
- `default_score`: checks `has_source`, `has_license_class`, `has_data`, `has_timestamp`, `has_lineage` → score 0..1.
- Scorer must return dict with `score` (0..1 float); `min_score` floor enforced.
- Key validation: keys must be 64 hex chars; path traversal attempts refused everywhere.

**Invariants:**
- **All or nothing**: a save lands on all three sources or on none (rollback).
- **Read-back verification**: every source must return byte-identical data on read-back.
- **DAG linkage**: content entry carries `data_sha256`, `capsule_prefix_hash`, `predecessor`, `size_bytes`, `score`. Location entries carry `readback_sha256` matching content.
- **Distinct sources**: constructor refuses nested or identical roots.

### 3.10 `vega_custody.proc`

**Role:** Run an untrusted program with bounded output, a wall-clock limit, and a VERIFIED kill. Shared by every repo that runs inbound or contained code.

**Public interface:**
- `run_bounded(argv, stdin_bytes=b"", timeout=10.0, cap=65536, cwd=None, env=None) -> dict` with keys: `status` (`ok`|`timeout`|`overflow`), `out`, `err`, `returncode`, `killed`, `kill_confirmed`.
- `ProcessJob` class with `start()`, `survivors()`, `kill(wait)`, `close()`.

**Behavior:**
- Output read in chunks (64 KB), never held beyond `cap+1` bytes per stream.
- On timeout/overflow: kills the whole process tree (Windows: job object with kill-on-close; POSIX: process group + SIGKILL), then confirms kill via `wait()`.
- `ProcessJob` on Windows uses a job object with active process limit and per-process memory limit; program started suspended, placed in job, then resumed. On POSIX uses process group + new session (best portable stand-in; a descendant that calls `setsid` can leave — `survivors()` is the guard).

**Invariants:**
- **Verified kill**: `kill_confirmed` is `True` only if the process tree is confirmed gone.
- **Process control, not OS sandbox**: does not block files or network. Hostile code belongs in a VM or container (docstring states this honestly).

### 3.11 `vega_custody.safepaths`

**Role:** The few filesystem rules every builder in the family follows. Third-party repos and manifests are untrusted input.

**Public interface:**
- `safe_name(name) -> str` — plain path component (no separators, no `..`, no control chars, no Windows device names, no trailing dot/space).
- `contained(root, *parts) -> str` — resolves symlinks, refuses unless result stays inside `root`.
- `read_capped(path, limit) -> bytes` — reads in chunks, refuses if file exceeds `limit` or grows past limit during read.
- `atomic_write(path, text, newline="
")` — writes to temp file in same directory, `os.replace` swaps in.

**Behavior:**
- `PathRefused` raised on any violation.
- Windows device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`..`COM9`, `LPT1`..`LPT9`) refused.

## 4. Guarantees and non-guarantees

### Guarantees (each names module + test)

| Guarantee | Module | Test |
|---|---|---|
| Capsule tamper detection (any field change) | capsule | `test_capsule.py` |
| Capsule chain order enforcement (predecessor linkage) | capsule | `test_capsule.py` |
| Forbidden metadata field names refused | capsule | `test_capsule.py` |
| Credential-shaped values in metadata refused | capsule | `test_capsule.py`, `redteam_5_audit_findings.py` |
| DAG append-only, no truncation | dag | `test_dag.py` (2 MB payload) |
| DAG replica byte-identity enforced | dag | `test_dag.py` |
| DAG record-or-refuse (partial write rolled back) | dag | `test_dag.py` (unwritable replica) |
| DAG tamper detected on verify and reopen | dag | `test_dag.py`, `redteam_1_chain_and_capsule.py` |
| DAG concurrent writers cannot fork | dag | `test_dag.py`, `redteam_1_chain_and_capsule.py` |
| Location read-back verification mandatory | locations | `test_dag.py` |
| Ledger single-use mint (leaf uniqueness) | ledger | `test_ledger.py` |
| Ledger metadata-only commitments (parameters refused) | ledger | `test_ledger.py` |
| Ledger verify fail-closed (tamper → False) | ledger | `test_ledger.py`, `redteam_2_ledger_and_store.py` |
| ReadOnlyLedger cannot mint or extend | ledger | `redteam_2_ledger_and_store.py` |
| Merkle proofs verify correctly; internal node ≠ leaf | merkle | `test_ledger.py`, `redteam_2_ledger_and_store.py` |
| Drive backend refuses unmounted drive / `/` anchor | backend_drive | `redteam_2_ledger_and_store.py` |
| Witness HTTPS-only, no redirects, root-only | backend_timestamp | `redteam_4_witness.py` |
| Store all-three-or-none with rollback | store | `test_store.py`, `redteam_2_ledger_and_store.py` |
| Store audit detects missing/corrupt copies | store | `test_store.py`, `redteam_2_ledger_and_store.py` |
| Store distinct source roots enforced | store | `redteam_2_ledger_and_store.py` |
| Bounded process output cap + verified kill | proc | `redteam_3_proc.py` |
| Grandchild kill confirmed | proc | `redteam_3_proc.py` |
| Safe name: Windows devices, trailing dot/space refused | safepaths | `redteam_5_audit_findings.py` |
| Contained: symlink-resolved path inside root | safepaths | (used by DKG builders) |
| Read capped: refuses oversize files | safepaths | (used by DKG builders) |

### Non-guarantees

| Non-guarantee | Why |
|---|---|
| Recorded content is true | Hash chain proves order/tamper, not truth of payload. |
| External drive / server are trustworthy | Only as safe as their operators. |
| Public-chain anchoring beyond local/drive/timestamp | Interfaces only, not built (STATUS.md). |
| OS-level containment | Process control only; hostile code needs VM/container. |
| Cryptographic expert review | Not done; code written for clarity. |
| Legal advice | License matrix is policy, not legal advice. |
| Truncation detection without external head | A truncated chain is still internally valid; only a remembered head or length exposes it (by design). |

## 5. Failure modes (from tests)

| Failure mode | What happens | Test |
|---|---|---|
| Capsule field tampered | `verify` raises `CapsuleError` | `test_capsule.py` |
| Capsule chain reordered | `verify_chain` raises `CapsuleError` | `test_capsule.py` |
| Capsule predecessor dropped | `verify_chain` raises `CapsuleError` | `test_capsule.py` |
| Metadata carries forbidden field name | `make` raises `CapsuleError` | `test_capsule.py` |
| Metadata carries credential-shaped value | `make` raises `CapsuleError` | `test_capsule.py`, `redteam_5_audit_findings.py` |
| DAG entry with unknown parent | `record` raises `RecordRefused` | `test_dag.py` |
| DAG payload carries forbidden field / credential | `record` raises `RecordRefused` | `test_dag.py`, `redteam_1_chain_and_capsule.py` |
| One replica unwritable | `record` raises `RecordRefused`, primary rolled back | `test_dag.py` |
| One replica tampered | `verify` returns `(False, problems)`, reopen raises `ChainBroken` | `test_dag.py`, `redteam_1_chain_and_capsule.py` |
| Stale second writer forks | `record` raises `RecordRefused`, chain intact | `test_dag.py`, `redteam_1_chain_and_capsule.py` |
| Ledger duplicate mint (same leaf) | `mint` raises `LedgerRefused` | `test_ledger.py` |
| Ledger commitment carries parameters | `mint` raises `LedgerRefused` | `test_ledger.py` |
| Ledger required drive missing | `Ledger` init raises `LedgerUnavailable` | `test_ledger.py` |
| Ledger optional drive missing | `Ledger` runs, `degraded` includes `"drive"` | `test_ledger.py` |
| Ledger tampered | `verify` returns `False`, reopen raises `LedgerUnavailable` | `test_ledger.py`, `redteam_2_ledger_and_store.py` |
| Witness redirect attempted | `OpenTimestampsWitness` refuses (no redirect handler) | `redteam_4_witness.py` |
| Witness non-HTTPS URL | Constructor raises `ValueError` | `redteam_4_witness.py` |
| Store one source corrupts write | `save` raises `StoreRefused`, other sources rolled back | `test_store.py` |
| Store one source down | `save` raises `StoreRefused` | `test_store.py` |
| Store source paths nested/identical | `ThreeSourceStore` init raises `StoreRefused` | `redteam_2_ledger_and_store.py` |
| Store key path traversal | `load`/`audit`/`DirBackend.get` raise `StoreRefused` | `redteam_2_ledger_and_store.py` |
| Proc child floods output | `status="overflow"`, `kill_confirmed=True`, output capped | `redteam_3_proc.py` |
| Proc child hangs | `status="timeout"`, `kill_confirmed=True` | `redteam_3_proc.py` |
| Proc grandchild survives | `kill_confirmed=True`, grandchild marker not created | `redteam_3_proc.py` |

## 6. Dependencies and layer rules

Registry entry (verbatim from ORGANISM_MAP.md):
```
vega-custody-sdk | 0 record | —
```

Dependencies point **down layers only**, never up or sideways. This kit has no dependencies (layer 0). Every other SDK in the family depends on custody.

## 7. Conformance

A third party can verify conformance by running the test suite:

```bash
export PYTHONPATH="$PWD/src:$PYTHONPATH"
python3 tests/test_capsule.py
python3 tests/test_dag.py
python3 tests/test_ledger.py
python3 tests/test_store.py
python3 tests/redteam_1_chain_and_capsule.py
python3 tests/redteam_2_ledger_and_store.py
python3 tests/redteam_3_proc.py
python3 tests/redteam_4_witness.py
python3 tests/redteam_5_audit_findings.py
```

**What passing means:** Every test exits 0. The published reference implementation behaves as specified for the tested scenarios (tamper detection, record-or-refuse, single-use mint, three-source save, bounded process kill, credential scan, etc.).

**What passing does NOT mean:**
- The code is hardened for production.
- The cryptography has been independently reviewed.
- The design covers threats outside the tested scenarios (e.g., side channels, hardware faults, supply chain).
- Public-chain anchoring works (those backends are interfaces only).
- The license is final (draft, not attorney-reviewed).
- This kit decides what actions are allowed (it does not; that is the governance jacket).
