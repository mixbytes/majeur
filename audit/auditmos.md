# Auditmos Security Skills — Moloch.sol

**Skill:** [auditmos/skills](https://github.com/auditmos/skills) (14 specialized audit skills)
**Type:** Multi-skill checklist-driven audit
**Target:** `src/Moloch.sol` (2110 lines, 5 contracts)
**Date:** 2026-03-11
**Methodology:** 6 applicable skills applied (of 14 total), each with structured checklist + reference patterns + severity criteria

---

## Skill Applicability Assessment

| Skill | Applicable? | Rationale |
|---|---|---|
| **audit-reentrancy** | Yes | EIP-1153 transient guard, external calls in _execute, _payout, ragequit |
| **audit-state-validation** | Yes | onlyDAO access control, init validation, state transitions |
| **audit-math-precision** | Yes | Assembly mulDiv, unchecked blocks, rounding in ragequit/futarchy |
| **audit-signature** | Partial | No EIP-712 signatures, but ERC-6909 permits exist |
| **audit-staking** | Partial | Futarchy rewards analogous to staking reward distribution |
| **always-checklist** | Yes | Token compatibility, CEI pattern, access control |
| audit-lending | No | No lending/borrowing |
| audit-liquidation (×4) | No | No liquidation mechanics |
| audit-clm | No | No concentrated liquidity |
| audit-auction | No | No auction mechanics |
| audit-oracle | No | No oracle dependency |
| audit-slippage | Partial | buyShares has maxPay; no DEX integration |

---

## Skill 1: audit-reentrancy

### Checklist Results

| # | Check | Status | Details |
|---|---|---|---|
| 1 | CEI pattern: state changes before external calls | PASS | All state-modifying functions follow CEI — e.g., `executeByVotes` sets `executed[id] = true` (line 519) before `_execute` (line 521); `ragequit` burns shares (line 773-774) before `_payout` (line 794) |
| 2 | NonReentrant modifiers on vulnerable functions | PASS | Applied to: `executeByVotes`, `spendPermit`, `buyShares`, `ragequit`, `cashOutFutarchy`, `spendAllowance` |
| 3 | No assumptions about token transfer behavior | PASS | `safeTransfer`/`safeTransferFrom` use Solady-style assembly — handles USDT, missing returns |
| 4 | Cross-function reentrancy: shared state protected | PASS | `nonReentrant` uses EIP-1153 transient storage (line 1003-1015), shared across all protected functions within same tx |
| 5 | Read-only reentrancy risks evaluated | PASS | View functions (`state()`, `balanceOf`) read finalized state; no price-oracle-like view dependencies |

### Reference Pattern Analysis

**Pattern #1 — Token Transfer Reentrancy:** `_payout` (line 988-999) makes external calls (`safeTransfer`, `safeTransferETH`, `mintFromMoloch`). State updates (burn, `executed` latch) happen BEFORE these calls. CEI enforced.

**Pattern #2 — State Update After External Call:** `ragequit` burns shares at lines 773-774 before the token payout loop at line 780-795. `executeByVotes` sets `executed[id] = true` at line 519 before `_execute` at line 521. Both correct.

**Pattern #3 — Cross-Function Reentrancy:** The EIP-1153 transient guard prevents re-entering any `nonReentrant` function during a protected call. `multicall` uses `delegatecall` which shares transient storage context — sub-calls to `nonReentrant` functions work correctly (each enters/exits independently within the same delegatecall context).

**Pattern #4 — Read-Only Reentrancy:** `state()` reads `tallies`, `supplySnapshot`, and config. None of these are mid-update during external calls — state is finalized before any external interaction.

### Findings

**0 findings.** All 4 reentrancy patterns are properly mitigated.

---

## Skill 2: audit-state-validation

### Checklist Results

| # | Check | Status | Details |
|---|---|---|---|
| 1 | Multi-step processes verify previous steps | PASS | `executeByVotes` checks `state(id)` (line 504-507) before execution; `queue` checks `Succeeded` state (line 483) |
| 2 | Functions validate array lengths > 0 | PASS | `ragequit` requires `tokens.length != 0` (line 766); `init` requires `initHolders.length == initShares.length` (line 221) |
| 3 | All function inputs validated for edge cases | PARTIAL | `init()` does not validate `quorumBps` range (line 226) — `setQuorumBps` validates at line 814 |
| 4 | Return values from all calls checked | PASS | `_execute` reverts on failure (line 985); `init` calls check `ok` (line 245) |
| 5 | State transitions atomic | PASS | Proposal state machine is deterministic via `state()` function |
| 6 | ID existence verified before use | PASS | `castVote` auto-opens proposals via `openProposal` (line 352); `cancelVote` checks `hasVoted != 0` (line 399) |
| 7 | Array parameters have matching length validation | PASS | `init` at line 221 |
| 8 | Access control on all administrative functions | PASS | All settings functions use `onlyDAO` modifier |
| 9 | State variables updated before external calls (CEI) | PASS | See audit-reentrancy above |
| 10 | Pause mechanisms synchronized | N/A | No pause mechanism — ragequit is the exit mechanism |
| 11 | Grace periods after unpause | N/A | No pause/unpause |

### Reference Pattern Analysis

**Pattern #1 — Unchecked 2-Step Ownership Transfer:** N/A. No ownership transfer — `onlyDAO` is `msg.sender == address(this)` (self-governance). The SUMMONER is set immutably in constructor.

**Pattern #2 — Unexpected Matching Inputs:** `ragequit` requires sorted token array with no duplicates (line 787: `if (i != 0 && tk <= prev) revert NotOk()`). Prevents double-counting.

**Pattern #3 — Unexpected Empty Inputs:** `ragequit` requires non-zero shares or loot to burn (line 767). `buyShares` requires `shareAmount != 0` (line 711). `fundFutarchy` requires `amount != 0` (line 531).

**Pattern #4 — Unchecked Return Values:** `_execute` checks `ok` and reverts (line 985). `safeTransfer`/`safeTransferFrom` use assembly with return value validation.

**Pattern #5 — Non-Existent ID Manipulation:** Proposal IDs are content-addressed hashes via `_intentHashId` (line 966-973). Operating on a non-existent ID hits default state (Unopened), which is handled by `state()` checks.

**Pattern #6 — Missing Access Control:** All settings functions are `onlyDAO`. `cancelProposal` requires `proposerOf[id]`. `castVote` requires non-zero voting weight.

**Pattern #7 — Inconsistent Array Length Validation:** `init` validates `initHolders.length == initShares.length` (line 221). `ragequit` has only one array parameter.

**Pattern #8 — Improper Pause Mechanism:** N/A — no pause. Ragequit serves as the exit mechanism (Moloch pattern).

### Findings

**1 finding (Low):**

**L-1: init() missing quorumBps range validation**
- **Pattern:** #3 (Unexpected empty inputs) / #5 (Non-existent ID manipulation)
- **Location:** `src/Moloch.sol:226`
- **Description:** `init()` accepts any `_quorumBps` value without validating the 0-10000 range. `setQuorumBps()` at line 814 correctly validates `bps > 10_000`.
- **Impact:** Deployer could set invalid quorum during initialization. Only callable by SUMMONER (privileged).
- **Severity:** Low — admin-only initialization, per Auditmos severity criteria: "Admin-only setter functions with missing validation are MEDIUM or LOW severity unless they brick user operations."

> **Review:** Valid hardening item. (Duplicate: Trail of Bits #2.1, QuillShield IAS-1)

---

## Skill 3: audit-math-precision

### Checklist Results

| # | Check | Status | Details |
|---|---|---|---|
| 1 | Multiplication before division | PASS | `mulDiv` (assembly) multiplies first: `prod0 = x * y` then divides (lines ~2020-2060) |
| 2 | Checks for rounding to zero with reverts | PARTIAL | `ragequit` line 792: `if (due == 0) continue` — skips zero amounts rather than reverting. This is correct behavior (skip dust). |
| 3 | Token amounts scaled to common precision | N/A | Single-token math per operation |
| 4 | No double-scaling | PASS | `futarchy.payoutPerUnit` scaled once by 1e18 (line 620), applied once (line 596) |
| 5 | Consistent precision scaling | PASS | 1e18 scaling used consistently in futarchy |
| 6 | SafeCast for downcasting | PARTIAL | `uint96(shares.getPastVotes(...))` at line 369 — direct downcast. Shares uses uint256 internally; uint96 max is ~79 billion tokens. Overflow would require >79B share units. |
| 7 | Protocol fees round up, user amounts round down | N/A | No fee mechanism in core governance |
| 8 | Decimal assumptions documented | N/A | No multi-decimal token math |
| 9 | Interest calculations use correct time units | N/A | No interest calculations |
| 10 | Token pair directions consistent | N/A | No oracle/price pair calculations |

### Reference Pattern Analysis

**Pattern #1 — Division Before Multiplication:** `mulDiv` uses assembly with multiply-first pattern. `mulDiv(pool, 1e18, winSupply)` at line 620 and `mulDiv(amount, F.payoutPerUnit, 1e18)` at line 596 — both multiply first.

**Pattern #2 — Rounding Down To Zero:** `ragequit` computes `due = mulDiv(pool, amt, total)` (line 791). If `pool * amt < total`, due rounds to zero and is skipped. This is correct behavior — the user receives zero of that token, which is expected for dust balances.

**Pattern #4 — Downcast Overflow:** `uint96(shares.getPastVotes(...))` at line 369 truncates silently if votes exceed uint96.max (~79.2 billion). This is practically unreachable for governance tokens but theoretically possible.

**Pattern #6 — Unsafe Downcasting:** `toUint48(block.number - 1)` at line 290. `uint48.max = 281 trillion` — block numbers won't reach this for millennia. Safe.

### Findings

**1 finding (Informational):**

**I-1: Unchecked uint96 downcast on voting weight**
- **Pattern:** #6 (Downcast overflow)
- **Location:** `src/Moloch.sol:369`
- **Description:** `uint96 weight = uint96(shares.getPastVotes(msg.sender, snap))` — truncates silently if voting power exceeds uint96.max (79,228,162,514 × 10^9).
- **Impact:** Practically unreachable. Would require >79 billion governance tokens with 18 decimals. Even with 10^18 scaling, this represents 79 billion full tokens.
- **Severity:** Informational — per Auditmos criteria: "admin-only precision issues, no security impact."

> **Review:** Practically unreachable. The uint96 range accommodates any realistic token supply. Not a vulnerability.

---

## Skill 4: audit-signature (Partial)

### Checklist Results

| # | Check | Status | Details |
|---|---|---|---|
| 1 | All signatures include nonces | N/A | No EIP-712 signature verification in contract |
| 2 | Nonces incremented after consumption | N/A | No signature nonces |
| 3 | chain_id in EIP-712 domain separator | N/A | No EIP-712 |
| 4 | All relevant parameters in signed messages | N/A | No signed messages |
| 5 | Signatures have deadlines | N/A | No signatures |
| 6 | Deadline validation | N/A | No signatures |
| 7 | ecrecover return value checked | N/A | No ecrecover |
| 8 | OZ ECDSA library for malleability | N/A | No signature verification |
| 9 | Signature verification before state changes | N/A | No signatures |
| 10 | No signature reuse after revocation | N/A | No signatures |

### Findings

**0 findings.** Moloch does not use EIP-712 signatures or ecrecover. The permit system uses ERC-6909 token burns (line 670: `_burn6909(msg.sender, tokenId, 1)`) rather than cryptographic signatures — a fundamentally different authorization model that avoids the entire signature vulnerability class.

---

## Skill 5: audit-staking (Partial — Futarchy Rewards)

### Checklist Results

| # | Check | Status | Details |
|---|---|---|---|
| 1 | Separate tokens: reward ≠ staking | PARTIAL | Futarchy can reward with minted shares/loot (same token type as governance). This is intentional — share dilution is the cost of incentivization. |
| 2 | No direct transfer dilution | PASS | Futarchy pool tracks `F.pool` (internal accounting), not raw balance |
| 3 | Precision protection: minimum stake | PASS | `castVote` requires `weight > 0` (line 370) — no zero-weight votes that could dilute |
| 4 | Flash protection: time locks | PASS | Voting power uses block N-1 snapshot — cannot flash-loan into futarchy rewards |
| 5 | Index updates: reward calc before/after | PASS | `payoutPerUnit` calculated once at resolution (line 620), immutable after |
| 6 | Balance integrity: cached balances updated | PASS | `_burn6909` in `cashOutFutarchy` (line 594) updates both balanceOf and totalSupply atomically |

### Findings

**0 findings.** Futarchy reward distribution is well-structured. The `payoutPerUnit` is calculated once at resolution and is immutable, preventing manipulation.

---

## Skill 6: always-checklist (Global)

### Reentrancy Protection

| Check | Status |
|---|---|
| State changes before external calls (CEI) | PASS |
| NonReentrant modifiers on vulnerable functions | PASS |
| No assumptions about token transfer behavior | PASS |
| Cross-function reentrancy considered | PASS |
| Read-only reentrancy risks evaluated | PASS |

### Token Compatibility

| Check | Status | Details |
|---|---|---|
| Fee-on-transfer tokens handled | PARTIAL | `buyShares` credits full `shareAmount` regardless of actual received. DAO selects sale token. |
| Rebasing tokens accounted for | N/A | No rebasing token integration |
| Tokens with callbacks (ERC777) considered | PASS | `nonReentrant` on all external-call functions |
| Zero transfer reverting tokens handled | PASS | `_payout` checks `amount == 0` and returns early (line 989) |
| Pausable tokens won't brick protocol | PARTIAL | A paused token in ragequit reverts the whole call; caller can omit it from array |
| Token decimals properly scaled | N/A | No multi-decimal math |
| Deflationary/inflationary tokens supported | PARTIAL | Fee-on-transfer in sales (same as above) |

### Access Control

| Check | Status | Details |
|---|---|---|
| Critical functions have appropriate modifiers | PASS | All settings: `onlyDAO`. Execute: governance-gated. |
| Two-step ownership transfer | N/A | No ownership — self-governance |
| Role-based permissions properly segregated | PASS | `onlyDAO` (governance), `proposerOf` (cancel), badge-gated (chat) |
| Emergency pause functionality | N/A | Ragequit is the exit mechanism; `bumpConfig()` invalidates proposals |
| Time delays for critical operations | PASS | `timelockDelay` configurable (line 41) |

### Findings from always-checklist

**1 finding (Low):**

**L-2: Fee-on-transfer token accounting in buyShares**
- **Location:** `src/Moloch.sol:741`
- **Description:** `safeTransferFrom(payToken, cost)` may transfer fewer tokens than `cost` if a fee-on-transfer token is used. The buyer receives full `shareAmount` worth of shares.
- **Impact:** DAO receives fewer tokens than expected. Governance selects the sale token (configuration-dependent).
- **Severity:** Low — per always-checklist: DAO-controlled configuration.

> **Review:** Valid informational concern. (Duplicate: QuillShield ECS-2)

---

## Consolidated Findings

| # | Finding | Skill | Severity | Triager Verdict | Prior Duplicates |
|---|---|---|---|---|---|
| L-1 | init() missing quorumBps range validation | audit-state-validation | Low | DISMISSED (admin-only) | Trail of Bits #2.1, QuillShield IAS-1 |
| I-1 | Unchecked uint96 downcast on voting weight | audit-math-precision | Informational | DISMISSED (unreachable) | None (new observation, not a vulnerability) |
| L-2 | Fee-on-transfer token accounting in buyShares | always-checklist | Low | DISMISSED (config-dependent) | QuillShield ECS-2 |

**Total: 0 Critical, 0 High, 0 Medium, 2 Low, 1 Informational**

---

## Skills Not Applied (Rationale)

| Skill | Why N/A |
|---|---|
| audit-lending | No lending/borrowing mechanics |
| audit-liquidation | No liquidation mechanisms |
| audit-liquidation-calculation | No liquidation calculations |
| audit-liquidation-dos | No liquidation to DoS |
| audit-unfair-liquidation | No liquidation incentives |
| audit-clm | No concentrated liquidity management |
| audit-auction | No auction mechanics (proposals are not auctions) |
| audit-oracle | No oracle dependency — voting power from on-chain checkpoints |

---

## HackenProof Triage Backtrack

- **L-1 (init quorumBps):** Already triaged as HackenProof Low (#6). No change.
- **I-1 (uint96 downcast):** New observation but not a vulnerability (practically unreachable). Below HackenProof's severity threshold — Out of Scope (Informational).
- **L-2 (fee-on-transfer):** Already triaged as HackenProof Low (#13). No change.

No changes to HackenProof triage report required.

---

## Verdict

Of Auditmos's 14 specialized audit skills, **6 are applicable** to Moloch.sol (governance/DAO). The 8 DeFi-specific skills (lending, liquidation, CLM, auction) are not applicable. Of the 6 applied skills, all checklists pass with only 2 Low findings and 1 Informational — all duplicates of prior audits except the uint96 downcast observation (practically unreachable, not a vulnerability).

The Auditmos skills are well-structured for DeFi protocol audits but lack a dedicated **governance/DAO audit skill** — the most relevant skill (audit-state-validation) covers general access control but misses governance-specific patterns like flash loan voting, quorum manipulation, delegation corruption, and proposal lifecycle attacks. For governance contracts, the Forefy and Archethect frameworks provide superior coverage.
