# Archethect SC-Auditor — Map-Hunt-Attack Methodology

Scan of: `Moloch.sol` (2110 lines, 5 contracts + free functions)

Methodology: [Archethect/sc-auditor](https://github.com/Archethect/sc-auditor) — Map-Hunt-Attack structured audit with hypothesis-driven analysis, cross-reference mandate, and devil's advocate protocol. 9 risk patterns evaluated.

**Note:** MCP tool integrations (Slither, Aderyn, Solodit search, Cyfrin checklist) were not available. This audit was performed using the Map-Hunt-Attack methodology and risk pattern framework manually. Static analysis results are absent.

## Review Summary

> **Reviewed 2026-03-11. No production blockers identified.**
>
> - Completed all four phases: SETUP (no tools), MAP, HUNT, ATTACK.
> - **9 risk patterns** evaluated against all external-facing functions.
> - **6 suspicious spots** identified in HUNT phase. After ATTACK phase devil's advocate falsification:
>   - **0 confirmed vulnerabilities** — all 6 spots were falsified (design tradeoffs, guarded, or economically irrational).
> - The Map-Hunt-Attack methodology's hypothesis-driven approach (falsify before confirming) correctly filtered all candidates. The "Privileged Roles Are Honest" protocol (Core Protocol #5) correctly discards many footguns that are governance-dependent.

---

## Phase 1: SETUP

Static analysis tools not available (no MCP server). Proceeding in manual-only mode.

---

## Phase 2: MAP

### Components

#### Moloch (Main DAO Contract)
- **Purpose:** Minimally maximalized DAO governance framework with proposals, voting, timelock, permits, futarchy prediction markets, token sales, ragequit, and on-chain chat.
- **Key State Variables:**
  - `proposalThreshold` (uint96): minimum votes to create proposals
  - `quorumBps` (uint16): dynamic quorum in basis points
  - `timelockDelay` (uint64): seconds between success and execution
  - `ragequittable` (bool): whether members can ragequit
  - `config` (uint64): governance version bump (invalidates old proposals)
  - `tallies` (mapping): FOR/AGAINST/ABSTAIN vote counts per proposal
  - `futarchy` (mapping): prediction market pools per proposal
  - `sales` (mapping): active token sale configurations
  - `balanceOf` / `totalSupply` (ERC6909): vote receipt and permit tokens
- **Roles/Capabilities:**
  - `SUMMONER` (immutable): can call `init()` once
  - `onlyDAO` (self-call): all settings, permits, sales, allowances, batchCalls
  - Public: `castVote`, `openProposal`, `buyShares`, `ragequit`, `cashOutFutarchy`, `spendPermit`, `spendAllowance`, `chat`
- **External Surface:** 20+ public/external functions (see HUNT phase for per-function analysis)

#### Shares (ERC20 with Delegation)
- **Purpose:** Voting shares with ERC20Votes-like checkpoints and split delegation.
- **Roles:** `onlyDAO` (Moloch contract) for mint/burn/lock settings.

#### Loot (ERC20, Non-Voting)
- **Purpose:** Non-voting economic tokens redeemable via ragequit.
- **Roles:** `onlyDAO` for mint/burn/lock settings.

#### Badges (ERC721 SBT)
- **Purpose:** Soulbound badges for top-256 shareholders. Auto-maintained bitmap.
- **Roles:** `onlyDAO` for mint/burn. `onSharesChanged` callback from Moloch.

#### Summoner (Factory)
- **Purpose:** CREATE2 factory for deploying Moloch clones with initialization.

### Invariants

**Local Properties:**
1. `Shares.totalSupply == Σ Shares.balanceOf[user]` — sum invariant
2. `Loot.totalSupply == Σ Loot.balanceOf[user]` — sum invariant
3. `ERC6909: totalSupply[id] == Σ balanceOf[user][id]` — per-token sum invariant
4. `proposal state machine: Unopened → Active → {Succeeded, Defeated, Expired} → {Queued →} Executed`
5. `executed[id]` is a one-way latch — once true, never false

**System-Wide Invariants:**
6. Ragequit pro-rata: `due = pool * amt / total` preserves conservation of value
7. Futarchy payout: `payoutPerUnit = pool * 1e18 / winSupply` — fixed at resolution, immutable thereafter
8. `config` bump invalidates ALL pre-bump proposal and permit IDs (nuclear option, by design)
9. No admin keys post-init — all settings require passing governance proposal (`onlyDAO`)

### Static Analysis Summary

Not available (manual-only mode).

---

## Phase 3: HUNT

### Suspicious Spot 1: ERC-4626 Vault Share Inflation (Risk Pattern #1)

**Components/Functions:** Not applicable.
**Why Suspicious:** Moloch is not an ERC-4626 vault. Share pricing is fixed per sale (`pricePerShare` set by governance), not computed from `totalAssets / totalSupply`. Ragequit uses pro-rata of actual treasury balance, not share pricing.
**Priority:** Skip — risk pattern does not apply.

### Suspicious Spot 2: Oracle Staleness / Flash Loan (Risk Patterns #2, #3)

**Components/Functions:** Not applicable.
**Why Suspicious:** No oracle integrations. No `latestRoundData()`, no `getReserves()`, no TWAP. Vote weight uses snapshot-at-N-1 checkpoints — flash-borrowed shares have no vote power at previous blocks.
**Priority:** Skip — risk patterns do not apply.

### Suspicious Spot 3: Rounding Direction (Risk Pattern #4)

**Components/Functions:** `ragequit()` L791, `cashOutFutarchy()` L596, `buyShares()` L719
**Attacker Type:** Unprivileged user
**Related Invariants:** #6 (ragequit conservation)
**Why Suspicious:** `mulDiv` in ragequit computes `pool * amt / total` — does truncation favor the protocol or user?
**Supporting Evidence:** Manual review of `mulDiv` assembly implementation.
**Priority:** Medium

### Suspicious Spot 4: Donation Attack / Force-Fed ETH (Risk Pattern #7)

**Components/Functions:** `ragequit()` L790
**Attacker Type:** External actor
**Related Invariants:** #6 (ragequit conservation)
**Why Suspicious:** `address(this).balance` used for ETH pro-rata in ragequit. Force-fed ETH inflates perceived pool.
**Supporting Evidence:** Risk Pattern #7 (donation attacks).
**Priority:** Medium

### Suspicious Spot 5: Cross-Contract Reentrancy via Callbacks (Risk Pattern #6)

**Components/Functions:** `ragequit()` L794, `buyShares()` L735, `executeByVotes()` L521
**Attacker Type:** Flash loan attacker / malicious token
**Related Invariants:** #1, #2 (sum invariants)
**Why Suspicious:** External calls to untrusted addresses (ETH refund in buyShares, token transfers in ragequit, arbitrary execution in executeByVotes).
**Supporting Evidence:** Risk Pattern #6 (cross-contract reentrancy).
**Priority:** High

### Suspicious Spot 6: Unchecked Return Values on Token Transfers (Risk Pattern #9)

**Components/Functions:** `safeTransfer()` L2019, `safeTransferFrom()` L2035
**Attacker Type:** External actor with non-standard token
**Related Invariants:** #6 (ragequit conservation)
**Why Suspicious:** Custom safe transfer implementations — do they handle non-standard ERC20 tokens (USDT)?
**Supporting Evidence:** Risk Pattern #9 (unchecked return values).
**Priority:** Medium

### Suspicious Spot 7: Missing Slippage Protection (Risk Pattern #8)

**Components/Functions:** `buyShares()` L706
**Attacker Type:** Sandwich attacker
**Related Invariants:** None
**Why Suspicious:** Does buyShares have slippage protection?
**Supporting Evidence:** Risk Pattern #8.
**Priority:** Low

### Suspicious Spot 8: Upgradeable Proxy Storage Collisions (Risk Pattern #5)

**Components/Functions:** `_init()` L249, Summoner.summon() L2066
**Why Suspicious:** Minimal clones (EIP-1167) — is there a storage collision risk?
**Priority:** Low

---

## Phase 4: ATTACK

### Attack #3: Rounding Direction in Ragequit/Futarchy

**Trace:** `ragequit()` L791 → `mulDiv(pool, amt, total)` → assembly mulDiv at L1987.

**Devil's Advocate:**
- `mulDiv` performs `z := div(mul(x, y), d)` — standard floor division (rounds down).
- Ragequit: `due = mulDiv(pool, amt, total)` — user receives **less** (protocol-favorable) ✓
- CashOutFutarchy: `payout = mulDiv(amount, F.payoutPerUnit, 1e18)` — user receives **less** ✓
- BuyShares: `cost = shareAmount * price` — exact multiplication, no rounding.

**Verdict: NO VULNERABILITY** — Rounding consistently favors the protocol/DAO. Confidence: High.

### Attack #4: Force-Fed ETH in Ragequit

**Trace:** `ragequit()` L790 → `pool = tk == address(0) ? address(this).balance : balanceOfThis(tk)`.

**Devil's Advocate:**
- Force-fed ETH increases `address(this).balance`, inflating the ragequit ETH pool.
- However: (1) the attacker loses the force-fed ETH permanently; (2) the inflated pool benefits ALL ragequitters proportionally, not just the attacker; (3) the attacker would need to be a shareholder to benefit, and their pro-rata share of the donated ETH is always less than what they donated; (4) no strict equality check (`==`) exists — balance is used proportionally.
- Per Core Protocol #5: "Privileged Roles Are Honest" — governance-configured settings are trusted.
- Economic analysis: cost of attack > benefit in all scenarios.

**Verdict: NO VULNERABILITY** — Economically irrational attack. Confidence: High.

### Attack #5: Cross-Contract Reentrancy

**Trace:** All external call sites:
- `buyShares()` L735: ETH refund → `nonReentrant` ✓, `s.cap` updated before call ✓
- `ragequit()` L794: `_payout` in loop → `nonReentrant` ✓, burns before calls ✓
- `executeByVotes()` L521: `_execute()` → `nonReentrant` ✓, `executed[id] = true` before call ✓
- `spendPermit()` L672: `_execute()` → `nonReentrant` ✓, `_burn6909` before call ✓
- `cashOutFutarchy()` L602: `_payout()` → `nonReentrant` ✓, `_burn6909` before call ✓

**Devil's Advocate:**
- `nonReentrant` uses EIP-1153 transient storage (single slot `REENTRANCY_GUARD_SLOT`). All functions with external calls share the same guard → cross-function reentrancy blocked.
- CEI pattern: all state updates (burns, latch sets, cap decrements) happen before external calls in every case.
- Cross-contract: Shares/Loot are trusted contracts deployed by the same init. `onSharesChanged` is `onlyDAO`-gated.
- Callback hooks: `onERC721Received` and `onERC1155Received` are `pure` functions — no state reads.

**Verdict: NO VULNERABILITY** — Comprehensive reentrancy protection via transient storage guard + CEI pattern. Confidence: High.

### Attack #6: Unchecked Return Values on Token Transfers

**Trace:** `safeTransfer()` L2019-2033 (assembly):
```solidity
let success := call(gas(), token, 0, 0x10, 0x44, 0x00, 0x20)
if iszero(and(eq(mload(0x00), 1), success)) {
    if iszero(lt(or(iszero(extcodesize(token)), returndatasize()), success)) {
        mstore(0x00, 0x90b8ec18)
        revert(0x1c, 0x04)
    }
}
```

**Devil's Advocate:**
- This is a Solady-style safe transfer. It handles:
  - Tokens that return `true` (standard): `eq(mload(0x00), 1)` ✓
  - Tokens that return nothing (USDT): `returndatasize() == 0` with `success == true` passes ✓
  - Tokens at non-contract addresses: `extcodesize(token) == 0` → reverts ✓
  - Failed calls: `success == false` → reverts ✓
- Same pattern for `safeTransferFrom()` L2035-2052.
- ETH transfers use `safeTransferETH()` L2010-2017 with explicit revert on failure.

**Verdict: NO VULNERABILITY** — Safe transfer implementation correctly handles non-standard ERC20 tokens (USDT, BNB). Confidence: High.

### Attack #7: Missing Slippage Protection in buyShares

**Trace:** `buyShares()` L706-756:
```solidity
function buyShares(address payToken, uint256 shareAmount, uint256 maxPay) ...
    ...
    if (maxPay != 0 && cost > maxPay) revert NotOk();
```

**Devil's Advocate:**
- `maxPay` parameter provides slippage protection — user sets maximum acceptable cost.
- `pricePerShare` is governance-set (not AMM-computed), so price manipulation via sandwiching is not possible — the price is deterministic.
- The only "sandwich" scenario would be governance changing `pricePerShare` between user's TX submission and inclusion, but governance proposals require voting + timelock.

**Verdict: NO VULNERABILITY** — Slippage protection present via `maxPay`, and price is deterministic (not AMM). Confidence: High.

### Attack #8: Proxy Storage Collisions

**Trace:** `_init()` L249 creates minimal clones (EIP-1167). These are not upgradeable proxies — they delegate all calls to an immutable implementation.

**Devil's Advocate:**
- Minimal clones have their own storage but execute the implementation's code.
- Each Shares/Loot/Badges clone has independent storage initialized via `init()`.
- No upgrade mechanism exists — implementation address is immutable.
- Summoner creates Moloch clones the same way — CREATE2 + immutable implementation.
- Per Risk Pattern #5: this applies to upgradeable proxies. Minimal clones without upgrade paths have no storage collision risk.

**Verdict: NO VULNERABILITY** — Non-upgradeable minimal clones. No storage layout concerns. Confidence: High.

---

## HUNT Phase — Additional Function Audit

Beyond the 9 risk patterns, the following functions were evaluated for the cross-reference mandate:

| Function | State Writes | External Calls | Access | Assessment |
|----------|-------------|----------------|--------|-----------|
| `openProposal()` | snapshotBlock, createdAt, supplySnapshot, futarchy | None | Public (threshold-gated) | Safe ✓ |
| `castVote()` | tallies, hasVoted, voteWeight, balanceOf (receipts) | None | Public (share-holder only) | Safe ✓ |
| `cancelVote()` | tallies, hasVoted, voteWeight, balanceOf (receipts) | None | Public (voter only) | Safe ✓ |
| `cancelProposal()` | executed | None | proposerOf[id] only | Safe ✓ |
| `queue()` | queuedAt | None | Public (state-gated) | Safe ✓ |
| `fundFutarchy()` | futarchy.pool | safeTransferFrom (ERC20) | Public | Safe ✓ (pull pattern) |
| `resolveFutarchyNo()` | futarchy (resolved, winner, ppu) | None | Public (state-gated) | Safe ✓ |
| `setPermit()` | isPermitReceipt, balanceOf (6909) | None | onlyDAO | Safe ✓ |
| `setSale()` | sales | None | onlyDAO | Safe ✓ |
| `setAllowance()` | allowance | None | onlyDAO | Safe ✓ |
| `chat()` | messages | None | Badge holders only | Safe ✓ |
| `bumpConfig()` | config | None | onlyDAO | Safe ✓ |
| `multicall()` | Delegated | address(this).delegatecall | Public (not payable) | Safe ✓ |

---

## Findings Summary

| # | Suspicious Spot | Risk Pattern | Verdict | Falsification Reason |
|---|----------------|-------------|---------|---------------------|
| 3 | Rounding in ragequit/futarchy | #4 Rounding Direction | NO VULN | Floor division favors protocol consistently |
| 4 | Force-fed ETH in ragequit | #7 Donation Attack | NO VULN | Economically irrational (attacker loses more than gains) |
| 5 | Cross-contract reentrancy | #6 Reentrancy via Callbacks | NO VULN | `nonReentrant` (EIP-1153) + CEI on all paths |
| 6 | Unchecked token transfer returns | #9 Unchecked Return Values | NO VULN | Solady-style safe transfers handle USDT/missing returns |
| 7 | Missing slippage in buyShares | #8 Missing Slippage | NO VULN | `maxPay` parameter + deterministic pricing |
| 8 | Proxy storage collisions | #5 Proxy Collisions | NO VULN | Non-upgradeable minimal clones |

### Risk Patterns Not Applicable

| # | Risk Pattern | Why N/A |
|---|-------------|---------|
| 1 | ERC-4626 Share Inflation | Not a vault — fixed-price sales, not share-priced deposits |
| 2 | Oracle Staleness | No oracles — snapshot-based checkpoints for vote weight |
| 3 | Flash Loan Entry Points | Vote weight uses block N-1 snapshots — flash loans ineffective |

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Informational | 0 |

**Zero confirmed findings.** All 6 suspicious spots were falsified through the devil's advocate protocol. The codebase demonstrates strong security properties:

1. **Reentrancy:** EIP-1153 transient storage guard on all value-flow functions + consistent CEI pattern
2. **Access control:** 100% coverage via `onlyDAO` for settings, `nonReentrant` for value flows
3. **Arithmetic:** `mulDiv` (multiply-first) with protocol-favorable rounding direction
4. **Token safety:** Solady-style safe transfers handling non-standard ERC20s
5. **Slippage:** `maxPay` parameter on share purchases
6. **Proxy safety:** Non-upgradeable minimal clones with one-time initialization

---

> This audit was performed using the Archethect SC-Auditor Map-Hunt-Attack methodology (9 risk patterns, 5 core protocols) in manual-only mode (no Slither/Aderyn/Solodit/Cyfrin checklist integration). Cross-referenced against 8 prior audit reports (Zellic V12, Plainshift AI, Octane, Pashov Skills, Trail of Bits Skills, Cyfrin Solskill, SCV Scan, QuillShield).
