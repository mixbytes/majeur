# SCV Scan — Smart Contract Vulnerability Scan

Scan of: `Moloch.sol` (2110 lines, 5 contracts + free functions)

Scanner: [kadenzipfel/scv-scan](https://github.com/kadenzipfel/scv-scan) — 36 vulnerability classes sourced from [smart-contract-vulnerabilities](https://github.com/kadenzipfel/smart-contract-vulnerabilities).

## Review Summary

> **Reviewed 2026-03-11. No production blockers identified.**
>
> - Scanned all 36 SCV vulnerability classes against Moloch.sol via the four-phase workflow (cheatsheet → syntactic grep → semantic analysis → deep validation).
> - **25 classes: Skip** — the vulnerability construct is absent from the codebase (e.g., no `tx.origin`, no `ecrecover`, no randomness, no ERC20 approve race, no inheritance chains, Solidity ≥0.8.0).
> - **11 classes: Survive** to deep validation. Of these:
>   - **3 confirmed findings** (all Informational/Low — design tradeoffs, not exploits)
>   - **8 discarded** after validation (false positive conditions met)
> - Cross-referenced against 6 prior audit reports (Zellic, Plainshift, Octane, Pashov, Trail of Bits, Cyfrin).

---

## Phase 2: Triage

### Skip (25 classes)

V1 Arbitrary Storage Location, V2 Asserting Contract from Code Size, V3 Authorization via tx.origin, V8 Incorrect Constructor Name, V14 Missing Protection Against Signature Replay, V16 Off-By-One, V17 Outdated Compiler Version, V20 Requirement Violation, V21 Shadowing State Variables, V23 Unencrypted Private Data On-Chain, V24 Unexpected ecrecover Null Address, V25 Uninitialized Storage Pointer, V28 Use of Deprecated Functions, V29 Weak Sources of Randomness, V30 Assert Violation, V31 Incorrect Inheritance Order, V32 Unsecure Signatures (Composite), V33 Signature Malleability, V34 Insufficient Gas Griefing, V9 Inadherence to Standards, V26 Unsupported Opcodes, V27 Unused Variables, V22 Timestamp Dependence, V35 Unsafe Low-Level Call, V36 DoS with (Unexpected) Revert.

### Survive (11 classes)

V4 Delegatecall to Untrusted Callee, V5 DoS with Block Gas Limit, V6 DoS with Revert (ragequit path), V7 Hash Collision with abi.encodePacked, V10 Insufficient Access Control, V11 Lack of Precision, V12 msg.value Reuse in Loops, V13 Transaction-Ordering Dependence, V15 Integer Overflow/Underflow, V18 Reentrancy, V19 Unchecked Return Values, V34 Unbounded Return Data.

Total: 36 classified.

---

## Phase 3: Deep Validation

### V4: Delegatecall to Untrusted Callee

**path:** `executeByVotes()` L493 → `_execute()` L976 → `to.delegatecall(data)` L983 | **guard:** requires passing governance vote (Succeeded/Queued state), `nonReentrant`, `executed` latch | **verdict:** DROP (FP: target is governance-controlled, not user-supplied — requires a passing proposal vote)

Also: `multicall()` L893 → `address(this).delegatecall(data[i])` L896 | **guard:** target is hardcoded `address(this)` | **verdict:** DROP (FP: target is immutable self-address)

### V5: DoS with Block Gas Limit

**path:** `ragequit()` L759 → iterates `tokens[]` L780 | **guard:** `tokens` is caller-supplied (not storage array), caller controls length | **verdict:** DROP (FP: bounded by caller, not unbounded storage)

**path:** `proposalIds.push()` L299 → unbounded storage array, but no on-chain function iterates it | `getProposalCount()` is O(1) | **verdict:** DROP (FP: array never iterated on-chain)

**path:** `Badges._recomputeMin()` L1911 → iterates `occupied` bitmap | **guard:** bitmap is max 256 bits (uint256), max 256 iterations | **verdict:** DROP (FP: bounded to 256)

### V6: DoS with Revert (ragequit path)

**path:** `ragequit()` L759 → `_payout()` L988 → `safeTransfer()` L2019 → reverts if blacklisted | **guard:** caller supplies `tokens[]` array and can omit problematic tokens | **verdict:** CONFIRM [Low] — see Finding 1

### V7: Hash Collision with abi.encodePacked

**path:** `_receiptId()` L962 → `keccak256(abi.encodePacked("Moloch:receipt", id, support))` | args: string literal (fixed), uint256 (fixed), uint8 (fixed) | **verdict:** DROP (FP: only one variable-length argument — string literal is compile-time constant, `id` and `support` are fixed-length)

### V10: Insufficient Access Control

**path:** All `set*()` functions (L813-882) have `onlyDAO` modifier. `init()` L209 has `require(msg.sender == SUMMONER)`. `buyShares()` is intentionally permissionless (guarded by sale config). `openProposal()` is gated by `proposalThreshold`. | **verdict:** DROP (FP: all state-changing functions properly gated)

**path:** `init()` L209 → no explicit `initializer` modifier | **guard:** `_init()` uses CREATE2 which fails on re-deployment; Shares/Loot `init()` checks `DAO == address(0)` | **verdict:** DROP (FP: re-initialization naturally prevented by clone creation and zero-address check)

### V11: Lack of Precision

**path:** `mulDiv()` L1987 → used for quorum calculation L468, ragequit pro-rata L791, futarchy payout L596, delegation allocation L1509 | **guard:** `mulDiv` multiplies before dividing (standard safe pattern) | **verdict:** DROP (FP: multiply-first pattern correctly applied)

### V12: msg.value Reuse in Loops

**path:** `multicall()` L893 → `delegatecall` in loop, preserves `msg.value` | **guard:** `multicall` is NOT `payable` — `msg.value` is always 0 | **verdict:** DROP (FP: non-payable function, `msg.value == 0` always)

Also: `batchCalls()` L885 → `.call{value: calls[i].value}` in loop | **guard:** `onlyDAO` — only callable via governance proposal; values come from the Call struct, not `msg.value` reuse | **verdict:** DROP (FP: per-call values from struct, not msg.value)

### V13: Transaction-Ordering Dependence (Frontrunning)

**path:** `buyShares()` L706 → token purchase with `maxPay` slippage parameter L721 | **guard:** `maxPay` parameter present | **verdict:** DROP (FP: slippage protection exists)

**path:** `castVote()` L347 → auto-opens proposal at block N-1 snapshot → vote ordering matters for futarchy outcomes | **guard:** snapshot at N-1 prevents same-block manipulation; quorum/majority needed | **verdict:** CONFIRM [Informational] — see Finding 2

### V15: Integer Overflow/Underflow (unchecked blocks)

**path:** Multiple `unchecked` blocks throughout. Key audit points:
- `unchecked { s.cap = cap - shareAmount; }` L725-727 — **guarded:** `cap != 0 && shareAmount > cap` check at L716
- `unchecked { balanceOf[to][id] += amount; }` L919 — **guarded:** totalSupply overflow checked, per-account ≤ totalSupply
- `unchecked { totalSupply[id] -= amount; }` L956 — **guarded:** balanceOf subtraction (checked) precedes this
- `unchecked { safeTransferETH(msg.sender, msg.value - cost); }` L734-735 — **guarded:** `msg.value >= cost` check at L732
- Tally increments L374-377: `unchecked { t.forVotes += weight; }` — bounded by total share supply (uint96 max = ~79B tokens at 18 decimals)
- `unchecked { ++config; }` L879-880 — uint64, would need 2^64 governance proposals to overflow

**Type downcasts:**
- `uint96(shares.getPastVotes(...))` L369 — **guarded:** Shares uses `toUint96()` safe cast internally, so return ≤ uint96 max
- `uint64(block.timestamp)` L292 — **safe:** block.timestamp won't exceed uint64 max until year ~584 billion
- `uint96 bal = uint96(bal256)` L1821 — **guarded:** `require(bal256 <= type(uint96).max, Overflow())` at L1820

**verdict:** DROP (FP: all unchecked blocks have proven bounds; all downcasts are validated)

### V18: Reentrancy

**path:** `buyShares()` L706 → ETH refund L735 (external call) before `shares.mintFromMoloch` L748 | **guard:** `nonReentrant` modifier | **verdict:** DROP (FP: reentrancy guard present)

**path:** `ragequit()` L759 → `_payout()` L794 (external calls in loop) | **guard:** `nonReentrant` modifier | **verdict:** DROP (FP: reentrancy guard present)

**path:** `executeByVotes()` L493 → `_execute()` L521 (arbitrary external call) | **guard:** `nonReentrant` modifier + `executed[id] = true` latch set before call | **verdict:** DROP (FP: reentrancy guard + state latch)

**path:** `init()` L209 → `initCalls[i].target.call` L244 (external calls in loop) | **guard:** callable only once (CREATE2 salt + Shares/Loot `DAO == address(0)` check); no state to re-enter against | **verdict:** DROP (FP: one-time initialization)

### V19: Unchecked Return Values

**path:** `init()` L244 → `(bool ok,) = initCalls[i].target.call{...}(...)` → `require(ok, NotOk())` — **checked**
**path:** `batchCalls()` L887 → `(bool ok,) = calls[i].target.call{...}(...)` → `require(ok, NotOk())` — **checked**
**path:** `_execute()` L976 → `(ok, retData) = to.call/delegatecall(...)` → `if (!ok) revert NotOk()` — **checked**
**path:** `safeTransferETH()` L2010 → assembly `call()` → `if iszero(...) revert` — **checked**
**path:** `safeTransfer()` L2019 → assembly `call()` → checked with extcodesize + returndatasize — **checked**
**verdict:** DROP (FP: all return values checked)

### V34: Unbounded Return Data

**path:** `_execute()` L976 → `to.call{value}(data)` returns `(bool ok, bytes memory retData)` → return data fully copied | **guard:** `to` is governance-approved (requires passing vote), not user-supplied | `executeByVotes` is `nonReentrant` | **verdict:** CONFIRM [Low] — see Finding 3

---

## Phase 4: Confirmed Findings

### 1. Blacklistable Token Can Force Ragequit Omission

**File:** `Moloch.sol` L780-794
**Severity:** Low

> **Review: Known concern. Duplicate of Pashov #9.** The caller supplies the `tokens[]` array and can omit any problematic token, forfeiting only their claim to that specific token. This is by design — the user-supplied token list is a feature that prevents a single blacklisted token from blocking the entire ragequit. Informational only.

**Description:** If a ragequitter is blacklisted by a token issuer (e.g., USDC, USDT) and includes that token in their `tokens[]` array, `safeTransfer` reverts and the entire ragequit fails. The mitigation is that callers can simply omit the problematic token from their array.

**Code:**
```solidity
for (uint256 i; i != tokens.length; ++i) {
    tk = tokens[i];
    // ...
    _payout(tk, msg.sender, due); // reverts if blacklisted for this token
}
```

**Recommendation:** UIs should warn users if a token in the treasury might cause a revert (blacklistable tokens) and offer to auto-exclude it from the ragequit token list.

---

### 2. Vote Ordering Affects Futarchy Outcomes

**File:** `Moloch.sol` L347-391
**Severity:** Informational

> **Review: Known design property. Duplicate of Trail of Bits #5.5 / Octane warning #15.** Futarchy receipt values depend on the order and timing of votes. This is inherent to any prediction market mechanism — early voters take positions before the outcome is known, and their receipt tokens represent those positions. The snapshot-at-N-1 mechanism prevents same-block share manipulation. Governance voting itself is not frontrunnable in a meaningful way since it requires real share ownership at the snapshot block.

**Description:** Vote ordering affects futarchy receipt distribution since ERC-6909 receipt tokens are minted proportional to vote weight at time of voting. Validators or MEV searchers could theoretically observe pending `castVote` transactions, though exploiting this requires actual share ownership at the snapshot block.

**Recommendation:** No code change needed. Futarchy is a prediction market by design — position ordering is expected behavior.

---

### 3. Unbounded Return Data on Governance Execution

**File:** `Moloch.sol` L976-986
**Severity:** Low

> **Review: Valid observation, minimal risk. The `_execute` function captures full return data from governance-approved targets.** Since the target address requires a passing governance vote (majority FOR, quorum met, potentially timelocked), the target is governance-approved — not arbitrary user input. A malicious return data attack would require first passing a governance proposal, at which point the attacker already controls the DAO via delegatecall (op=1) or arbitrary calls (op=0). The return data cost is borne by the executor, not the DAO itself. Assembly-bounded return copy would be a marginal hardening. **v2 consideration.**

**Description:** `_execute()` captures return data via Solidity's default `(bool ok, bytes memory retData)`, which copies all return data into memory. A governance-approved target could return excessive data, causing out-of-gas for the executor. However, the target is governance-approved (requires passing vote), making this a self-inflicted DoS at worst.

**Code:**
```solidity
function _execute(uint8 op, address to, uint256 value, bytes calldata data)
    internal
    returns (bool ok, bytes memory retData)
{
    if (op == 0) {
        (ok, retData) = to.call{value: value}(data);
    } else {
        (ok, retData) = to.delegatecall(data);
    }
    if (!ok) revert NotOk();
}
```

**Recommendation:** Consider using assembly to bound `returndatacopy` to a reasonable maximum (e.g., 4096 bytes), or use `ExcessivelySafeCall` for the `call` path. Low priority since the target is governance-approved.

---

## Discarded Candidates Summary

| Class | Location | Reason Discarded |
|-------|----------|-----------------|
| Delegatecall to Untrusted Callee | `_execute()`, `multicall()` | Target is governance-approved or hardcoded `address(this)` |
| DoS with Block Gas Limit | `proposalIds`, `ragequit`, `_recomputeMin` | Caller-supplied arrays, no on-chain iteration, bitmap bounded to 256 |
| Hash Collision (encodePacked) | `_receiptId()` | Only fixed-length arguments after the string literal |
| Insufficient Access Control | All `set*()`, `init()` | `onlyDAO` modifier on all settings; init guarded by SUMMONER + CREATE2 |
| Lack of Precision | `mulDiv()` usage | Multiply-first pattern correctly applied |
| msg.value Reuse | `multicall()`, `batchCalls()` | `multicall` not payable; `batchCalls` uses per-call struct values |
| Overflow/Underflow | 30 `unchecked` blocks | All bounds proven; all downcasts validated |
| Reentrancy | `buyShares`, `ragequit`, `executeByVotes` | `nonReentrant` (EIP-1153 transient storage) on all external-call paths |
| Unchecked Return Values | All `.call()` sites | All return values checked with require/revert |

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 2 |
| Informational | 1 |

---

> This scan was performed using the SCV Scan four-phase methodology (36 vulnerability classes) with manual deep validation and cross-referencing against 6 prior audit reports (Zellic V12, Plainshift AI, Octane, Pashov Skills, Trail of Bits Skills, Cyfrin Solskill).
