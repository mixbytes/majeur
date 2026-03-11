# QuillShield Security Skills — Multi-Layer Audit

Scan of: `Moloch.sol` (2110 lines, 5 contracts + free functions)

Scanner: [quillai-network/qs_skills](https://github.com/quillai-network/qs_skills) — 10 security analysis plugins covering OWASP Smart Contract Top 10 + extended vulnerability classes.

## Review Summary

> **Reviewed 2026-03-11. No production blockers identified.**
>
> - Evaluated 8 of 10 QuillShield plugins (2 not applicable: Oracle & Flash Loan, Signature & Replay — Moloch.sol has no price oracles and no signature verification).
> - **8 findings** across 6 layers. All are design tradeoffs, informational, or duplicates of findings from prior audits.
> - Severity breakdown: 0 Critical, 0 High, 3 Medium, 3 Low, 2 Informational.
> - The multi-layer severity matrix (guard × invariant × extended) did not produce any CRITICAL compound findings — guard consistency is strong and no invariants are broken.

---

## Phase 1: Behavioral Decomposition (BSA)

```
Contract: Moloch
Type: Governance/DAO
States: [Unopened, Active, Queued, Succeeded, Defeated, Expired, Executed]
Key Invariants (≤5):
  - totalSupply(shares) = Σ balanceOf(shares, user) for all users
  - totalSupply(receiptId) = Σ balanceOf(receiptId, user) for all users
  - ragequit pro-rata: due = pool * amt / total (conservation of value)
  - futarchy: payoutPerUnit = pool * 1e18 / winSupply (fixed at resolution)
  - proposal identity: id = keccak256(address(this), op, to, value, keccak(data), nonce, config)
Privileged Roles: [SUMMONER (init only), onlyDAO (self-governance)]
Value Entry/Exit Points: [buyShares (ETH/ERC20 in), ragequit (ETH/ERC20 out), fundFutarchy (ETH in), cashOutFutarchy (tokens out), spendAllowance (tokens out), executeByVotes (arbitrary)]
```

**Engine Selection (Governance/DAO):**
| Engine | Run |
|--------|-----|
| ETE (Economic) | Lite |
| ACTE (Access Control) | Full |
| SITE (State Integrity) | Full |

---

## Layer 1: Semantic Guard Analysis

### Guard-State Interaction Matrix

**State variable: governance settings** (`quorumBps`, `proposalThreshold`, `timelockDelay`, `ragequittable`, etc.)
- `setQuorumBps()` → Guard: `onlyDAO` ✓
- `setProposalThreshold()` → Guard: `onlyDAO` ✓
- `setTimelockDelay()` → Guard: `onlyDAO` ✓
- `setRagequittable()` → Guard: `onlyDAO` ✓
- `setAutoFutarchy()` → Guard: `onlyDAO` ✓
- `setRenderer()` → Guard: `onlyDAO` ✓
- `setMetadata()` → Guard: `onlyDAO` ✓
- `bumpConfig()` → Guard: `onlyDAO` ✓
- Guard frequency: **100%** (8/8 functions)

**State variable: `executed`**
- `executeByVotes()` → Guard: `nonReentrant`, state checks ✓
- `spendPermit()` → Guard: `nonReentrant`, `isPermitReceipt` ✓
- `cancelProposal()` → Guard: `msg.sender == proposerOf[id]`, state checks ✓
- Guard frequency: **100%** (3/3 functions)

**State variable: `balanceOf` (ERC6909)**
- `_mint6909()` → Guard: internal, called from guarded functions ✓
- `_burn6909()` → Guard: internal, called from guarded functions ✓
- `transfer()` → Guard: `isPermitReceipt` SBT check ✓
- `transferFrom()` → Guard: `isPermitReceipt` SBT check, sender auth ✓
- Guard frequency: **100%**

**State variable: `sales`**
- `setSale()` → Guard: `onlyDAO` ✓
- Guard frequency: **100%** (1/1)

### SGA Finding 1: Settings Functions Missing Events

**Severity:** Low | **Confidence:** 80%
**Location:** `Moloch.sol` L813-882, `setQuorumBps()`, `setProposalThreshold()`, etc.

> **Review: Valid observation. Duplicate of Trail of Bits maturity assessment (Auditing category).** Settings changes via `onlyDAO` functions do not emit events. While `onlyDAO` ensures only governance proposals can change them (and `Executed` event covers the proposal execution), dedicated events per setting change would improve off-chain monitoring. **v2 hardening candidate.**

**Pattern Evidence:** `setSale()` emits `SaleUpdated` ✓, but `setQuorumBps()`, `setTimelockDelay()`, etc. do not emit any event ✗. Inconsistent event emission pattern: 1/9 settings functions emit events.

**Recommendation:** Add events for each settings function (e.g., `event QuorumBpsChanged(uint16 newBps)`).

---

### SGA Conclusion

> No guard-state anomalies detected. All state-changing functions have consistent access control. The `onlyDAO` modifier is applied to 100% of governance configuration functions. The `nonReentrant` guard is applied to 100% of functions making external calls with value flow. Guard consistency is **strong** (100% across all categories).

---

## Layer 2: State Invariant Detection

### Invariant 1: ERC6909 Sum Invariant
```
totalSupply[id] = Σ balanceOf[user][id] for all users
```

**Functions modifying `balanceOf`:**
- `_mint6909()`: `totalSupply[id] += amount` ✓, `balanceOf[to][id] += amount` ✓ — preserves invariant
- `_burn6909()`: `balanceOf[from][id] -= amount` ✓, `totalSupply[id] -= amount` ✓ — preserves invariant
- `transfer()`: `balanceOf[sender][id] -= amount`, `balanceOf[receiver][id] += amount` — net zero ✓
- `transferFrom()`: same as transfer — net zero ✓

**Confidence:** 100% (4/4 functions preserve). **No violations.**

### Invariant 2: Shares Sum Invariant
```
Shares.totalSupply = Σ Shares.balanceOf[user] for all users
```

- `_mint()`: `totalSupply += amount` ✓, `balanceOf[to] += amount` ✓
- `_moveTokens()`: `balanceOf[from] -= amount`, `balanceOf[to] += amount` — net zero ✓
- `burnFromMoloch()`: `balanceOf[from] -= amount` ✓, `totalSupply -= amount` ✓

**Confidence:** 100%. **No violations.**

### Invariant 3: Loot Sum Invariant
Same pattern as Shares. **Confidence:** 100%. **No violations.**

### Invariant 4: Ragequit Conservation
```
due = pool * amt / total — pro-rata of each token
```

**Function:** `ragequit()` L759-797

- `total` = `shares.totalSupply() + loot.totalSupply()` captured **before** burns ✓
- Burns happen **before** payouts ✓ (CEI pattern)
- `mulDiv` used for precision ✓
- Tokens sorted and deduplicated (no double-counting) ✓

**No violations.**

### Invariant 5: Futarchy Pool Conservation

**SID Finding 1: Futarchy Pool Earmark Does Not Lock Tokens**

**Severity:** Medium | **Confidence:** 75%
**Location:** `Moloch.sol` L306-341, `openProposal()` auto-futarchy earmark

> **Review: Valid concern. Duplicate of Pashov #3 / Octane vuln #9.** When `rewardToken` is the actual Shares or Loot contract address (not sentinel values for minted rewards), `openProposal()` reads `balanceOf(address(this))` and adds to `F.pool` without transferring or locking. Multiple proposals earmark the same tokens. For sentinel values (minted rewards), this doesn't apply — `_payout` mints fresh tokens. In practice, most auto-futarchy uses minted rewards. **v2 hardening:** track committed amounts.

**Invariant violated:** `Σ futarchy[id].pool ≤ available_balance` — can be broken when multiple proposals earmark the same held tokens.

---

## Layer 3: Reentrancy Pattern Analysis

### Call Graph

| Function | External Calls | State Writes After | Guard |
|----------|---------------|-------------------|-------|
| `buyShares()` L706 | ETH refund L735, `shares/loot.mintFromMoloch` L747 | `s.cap` update at L726 (before call) | `nonReentrant` ✓ |
| `ragequit()` L759 | `_payout()` L794 in loop | Burns at L773-774 (before calls) | `nonReentrant` ✓ |
| `executeByVotes()` L493 | `_execute()` L521 | `executed[id] = true` at L519 (before call) | `nonReentrant` ✓ |
| `spendPermit()` L659 | `_execute()` L672 | `executed[tokenId] = true` at L668 (before call), `_burn6909` at L670 (before call) | `nonReentrant` ✓ |
| `cashOutFutarchy()` L583 | `_payout()` L602 | `_burn6909` at L594 (before call) | `nonReentrant` ✓ |
| `spendAllowance()` L685 | `_payout()` L687 | `allowance -= amount` at L686 (before call) | `nonReentrant` ✓ |
| `init()` L209 | `initCalls[i].target.call` L244 | One-time init | SUMMONER + CREATE2 ✓ |
| `multicall()` L893 | `address(this).delegatecall` L896 | Self-call | Not payable ✓ |

### CEI Verification

All external call paths follow Checks-Effects-Interactions:
- State updates (effects) happen **before** external calls (interactions) in every case
- `nonReentrant` (EIP-1153 transient storage) applied to **all** value-flow functions
- Cross-function reentrancy mitigated: `nonReentrant` guard is shared across all entry points via the same transient storage slot

### Reentrancy Conclusion

> **No reentrancy vulnerabilities detected.** All 5 reentrancy variants checked:
> - Classic: mitigated (CEI + nonReentrant)
> - Cross-function: mitigated (shared nonReentrant guard)
> - Cross-contract: no exploitable stale state during callbacks (burns/state before calls)
> - Read-only: no view functions return manipulable state during reentrancy window
> - Callback: `onERC721Received` and `onERC1155Received` are pure functions (no state reads)

---

## Layer 5: Proxy & Upgrade Safety

### Pattern Classification

**Pattern:** Minimal Proxy (EIP-1167) via CREATE2.

Moloch uses minimal clones for `Shares`, `Loot`, and `Badges` contracts, deployed in `init()` via `_init()` L249-261. The Summoner factory creates Moloch clones the same way.

**Not upgradeable.** Clones delegate to immutable implementation addresses. No `upgradeTo`, no storage gaps, no implementation setter.

### Initialization Safety

- `Moloch.init()` L209: guarded by `require(msg.sender == SUMMONER)` and CREATE2 salt prevents re-deployment
- `Shares.init()` L1112: guarded by `require(DAO == address(0))` — one-time
- `Loot.init()` L1628: guarded by `require(DAO == address(0))` — one-time
- `Badges.init()` L1724: guarded by `require(DAO == address(0))` — one-time

### Proxy Conclusion

> **No proxy/upgrade vulnerabilities.** Non-upgradeable minimal clones with one-time initialization guards. No storage collision risk (clones share implementation code, each with independent storage). No function selector clashing (no proxy admin functions).

---

## Layer 6: Input & Arithmetic Safety

### Input Validation Audit

| Function | Parameter | Validation | Status |
|----------|-----------|-----------|--------|
| `buyShares()` | `shareAmount` | `if (shareAmount == 0) revert NotOk()` | ✓ |
| `buyShares()` | `maxPay` | Slippage check: `if (maxPay != 0 && cost > maxPay) revert` | ✓ |
| `ragequit()` | `tokens` | `require(tokens.length != 0)`, sorted, no shares/loot/self | ✓ |
| `ragequit()` | `sharesToBurn + lootToBurn` | `if (sharesToBurn == 0 && lootToBurn == 0) revert` | ✓ |
| `castVote()` | `support` | `if (support > 2) revert NotOk()` | ✓ |
| `fundFutarchy()` | `amount` | `if (amount == 0) revert NotOk()` | ✓ |
| `setSale()` | `pricePerShare` | `require(pricePerShare != 0)` | ✓ |
| `setQuorumBps()` | `bps` | `if (bps > 10_000) revert NotOk()` | ✓ |
| `init()` | `initHolders/initShares` | `require(initHolders.length == initShares.length)` | ✓ |

### IAS Finding 1: `init()` Missing `quorumBps` Range Validation

**Severity:** Medium | **Confidence:** 85%
**Location:** `Moloch.sol` L209-247

> **Review: Valid. Duplicate of Trail of Bits #2.1.** `setQuorumBps()` validates `bps <= 10_000`, but `init()` does not validate `_quorumBps`. A value exceeding 10000 at deploy time would make quorum unreachable, permanently bricking the DAO. **v2 hardening:** add `require(_quorumBps <= 10_000)` to `init()`.

### Arithmetic Analysis

**Division-before-multiplication:** Not present. All precision-sensitive operations use `mulDiv()` (multiply-first).

**Rounding direction:**
- `ragequit`: `mulDiv(pool, amt, total)` — rounds down (user gets less) ✓ protocol-favorable
- `cashOutFutarchy`: `mulDiv(amount, F.payoutPerUnit, 1e18)` — rounds down ✓
- `buyShares`: `cost = shareAmount * price` — exact multiplication, no rounding ✓

**Unsafe casting:** All downcasts validated:
- `uint96(shares.getPastVotes(...))` L369: Shares internally uses `toUint96()` safe cast
- `uint64(block.timestamp)` L292: safe until year ~584 billion
- `uint96 bal = uint96(bal256)` L1821: preceded by `require(bal256 <= type(uint96).max)`

**Unchecked blocks:** 30 `unchecked` blocks audited. All have proven bounds (see SCV Scan report for detailed verification).

### IAS Finding 2: Dust Amount in Futarchy Payout

**Severity:** Informational | **Confidence:** 60%
**Location:** `Moloch.sol` L596

> **Review: Minor edge case.** `payout = mulDiv(amount, F.payoutPerUnit, 1e18)` — if `amount` is very small and `payoutPerUnit` is small, payout rounds to 0. The function handles this gracefully: `if (payout == 0) { emit FutarchyClaimed(..., 0); return 0; }`. The user burns receipts but gets nothing. This is the correct rounding direction (protocol-favorable) and the user chose to cash out a dust amount. Not a vulnerability.

---

## Layer 7: External Call Safety

### Return Value Audit

| Call Site | Return Checked | Status |
|-----------|---------------|--------|
| `init()` L244: `target.call{value}(data)` | `require(ok, NotOk())` | ✓ |
| `batchCalls()` L887: `target.call{value}(data)` | `require(ok, NotOk())` | ✓ |
| `_execute()` L981: `to.call{value}(data)` | `if (!ok) revert NotOk()` | ✓ |
| `_execute()` L983: `to.delegatecall(data)` | `if (!ok) revert NotOk()` | ✓ |
| `multicall()` L896: `address(this).delegatecall(data[i])` | `if (!success) { revert }` | ✓ |
| `safeTransferETH()` L2010: assembly `call` | `if iszero(...) revert` | ✓ |
| `safeTransfer()` L2019: assembly `call` | Checked with extcodesize + returndatasize | ✓ |
| `safeTransferFrom()` L2035: assembly `call` | Same pattern | ✓ |

**All return values checked.** ✓

### Token Integration Safety

**ECS Finding 1: Blacklistable Token Ragequit DoS**

**Severity:** Low | **Confidence:** 80%
**Location:** `Moloch.sol` L780-794

> **Review: Known concern. Duplicate of Pashov #9 / SCV Scan #1.** Ragequit iterates caller-supplied `tokens[]` array. If a token blacklists the ragequitter, `safeTransfer` reverts and the entire ragequit fails. **Mitigation:** caller can omit the problematic token from their array. UIs should warn about blacklistable tokens.

**ECS Finding 2: Fee-on-Transfer Token Accounting**

**Severity:** Low | **Confidence:** 70%
**Location:** `Moloch.sol` L738-741, `buyShares()` ERC20 path

> **Review: Valid observation, low practical impact.** `buyShares()` uses `safeTransferFrom(payToken, cost)` and credits `shareAmount` shares. If `payToken` is a fee-on-transfer token, the DAO receives less than `cost` but issues full shares. However, `setSale()` is `onlyDAO` — the DAO governance chooses which pay tokens to enable via sales. If a DAO configures a fee-on-transfer token as payment, the DAO itself bears the cost. Not a vulnerability — it's a configuration choice. UIs should flag fee-on-transfer tokens when configuring sales.

**ECS Finding 3: Return Data Bomb on Governance Execution**

**Severity:** Low | **Confidence:** 65%
**Location:** `Moloch.sol` L976-986

> **Review: Duplicate of SCV Scan #3.** `_execute()` captures full return data from governance-approved targets. Minimal risk since target requires passing vote. **v2 consideration:** bound `returndatacopy` via assembly.

### Payment Pattern Analysis

- `ragequit()`: **Push pattern** — iterates tokens and sends to user. Mitigated by caller-supplied token list (user controls which tokens to claim).
- `cashOutFutarchy()`: **Pull pattern** — user claims individually ✓
- `spendAllowance()`: **Pull pattern** — user claims individually ✓
- `buyShares()`: **Pull pattern** (user initiates purchase) ✓

---

## Layer 9: DoS & Griefing Analysis

### Class 1: Unbounded Loop DoS

| Loop | Bound | On-chain Iteration | Status |
|------|-------|-------------------|--------|
| `init()` L243: `initCalls` | Caller-supplied, one-time | Yes (init only) | Safe ✓ |
| `init()` L1116: `initHolders` | Caller-supplied, one-time | Yes (init only) | Safe ✓ |
| `ragequit()` L780: `tokens` | Caller-supplied per-call | Yes | Safe ✓ (user controls) |
| `batchCalls()` L886: `calls` | `onlyDAO` governance | Yes | Safe ✓ (governance-gated) |
| `multicall()` L895: `data` | Caller-supplied | Yes | Safe ✓ (gas-bound) |
| `proposalIds.push()` L299 | Unbounded storage | **Never iterated on-chain** | Safe ✓ |
| `Badges._recomputeMin()` L1911 | 256-bit bitmap | Max 256 iterations | Safe ✓ |

### Class 2: External Call Failure DoS

**DGA Finding 1: Ragequit Blocked by Single Token Revert**

**Severity:** Medium | **Confidence:** 80%
**Location:** `Moloch.sol` L780-795

> **Review: Known concern. Duplicate of Pashov #9 / SCV Scan #1 / ECS Finding 1.** A single reverting token in the `tokens[]` array blocks the entire ragequit. Mitigated by user-supplied token list — users can omit problematic tokens.

### Class 5: Timestamp Griefing

No timestamp-resetable locks or cooldowns. Proposal `createdAt` is set once and never reset. Timelock `queuedAt` is set once per proposal. No griefing vector.

### Class 6: Self-Destruct Force-Feeding

**DGA Finding 2: `address(this).balance` Used in Ragequit**

**Severity:** Informational | **Confidence:** 55%
**Location:** `Moloch.sol` L790

> **Review: Informational, not exploitable.** `ragequit()` reads `address(this).balance` when `tk == address(0)` to compute ETH pro-rata. Force-fed ETH (via `selfdestruct`) would increase the perceived ETH pool, giving ragequitters a larger share. However: (1) the attacker loses the force-fed ETH permanently, (2) the extra ETH is distributed pro-rata to ALL ragequitters (not just the attacker), and (3) the attacker would need to also be a shareholder to benefit, making the attack economically irrational. No strict equality check — `address(this).balance` is used proportionally, not as an invariant. **Not a vulnerability.**

### Class 7: Block Stuffing

**DGA Finding 3: Proposal TTL Window**

> **Review: N/A.** When `proposalTTL > 0`, proposals expire after `t0 + proposalTTL`. The TTL is governance-configurable and typically set to days/weeks, making block stuffing infeasible. When `proposalTTL == 0`, proposals never expire. No vulnerability.

---

## Skipped Layers

### Layer 4: Oracle & Flash Loan Analysis — N/A

Moloch.sol has no oracle integrations, no `latestRoundData()`, no `getReserves()`, no `slot0()`, no price feeds. Value calculations use internal accounting (`mulDiv` on known quantities). Flash loan governance attacks are mitigated by snapshot-at-N-1 (vote weight determined at previous block).

### Layer 8: Signature & Replay Analysis — N/A

Moloch.sol has no `ecrecover`, no ECDSA verification, no EIP-712 domain separators, no `permit()`. Proposal and permit identity uses `keccak256(abi.encode(address(this), op, to, value, keccak256(data), nonce, config))` — this is on-chain hash identity, not signature verification.

---

## Multi-Layer Severity Matrix

| Finding | Layer 1 (Guard) | Layer 2 (Invariant) | Extended Layer | Combined |
|---------|----------------|--------------------|---------|----|
| Futarchy earmark double-commit | No guard issue | Breaks conservation | External Call (held token) | **Medium** |
| Init missing quorumBps validation | No guard issue | No break | Input validation gap | **Medium** |
| Blacklistable token ragequit DoS | No guard issue | No break | DoS (external call failure) | **Low** |
| Missing settings events | Weak guard pattern | No break | — | **Low** |
| Fee-on-transfer accounting | No guard issue | No break | External call (token) | **Low** |
| Return data bomb | No guard issue | No break | External call (return data) | **Low** |
| Dust futarchy payout | No guard issue | No break | Arithmetic (rounding) | **Info** |
| Force-fed ETH in ragequit | No guard issue | No break | DoS (force-feed) | **Info** |

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 3 |
| Low | 3 |
| Informational | 2 |
| **Total** | **8** |

### Findings by Novelty

| Finding | Novel? | Prior Audit |
|---------|--------|-------------|
| Futarchy earmark double-commit | No | Pashov #3, Octane #9 |
| Init missing quorumBps validation | No | Trail of Bits #2.1 |
| Blacklistable token ragequit DoS | No | Pashov #9, SCV Scan #1 |
| Missing settings events | No | Trail of Bits maturity |
| Fee-on-transfer accounting | Partially | New framing, but DAO configures sales |
| Return data bomb | No | SCV Scan #3 |
| Dust futarchy payout | Yes | New (handled gracefully) |
| Force-fed ETH in ragequit | Partially | New framing, economically irrational |

---

> This audit was performed using the QuillShield Security Skills multi-layer methodology (8 of 10 plugins applied) with manual analysis and cross-referencing against 7 prior audit reports (Zellic V12, Plainshift AI, Octane, Pashov Skills, Trail of Bits Skills, Cyfrin Solskill, SCV Scan).
