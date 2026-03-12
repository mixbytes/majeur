# Archethect SC-Auditor — Map-Hunt-Attack Methodology

Scan of: `Moloch.sol` (2110 lines, 5 contracts + free functions) + peripheral contracts (DAICO.sol, Tribute.sol, Sale.sol, SafeSummoner.sol)

Methodology: [Archethect/sc-auditor v0.3.0](https://github.com/Archethect/sc-auditor) — Map-Hunt-Attack structured audit with hypothesis-driven analysis, cross-reference mandate, and devil's advocate protocol. 9 risk patterns evaluated.

**MCP Tools:**
- **Slither v0.11.5** — static analysis
- **Aderyn v0.1.9** — static analysis
- **Solodit Search** — 11 cross-reference queries against 20k+ real-world findings
- **Cyfrin Audit Checklist** — full checklist applied during HUNT phase

## Review Summary

> **Reviewed 2026-03-12. No production blockers identified.**
>
> - Completed all four phases: SETUP, MAP, HUNT, ATTACK.
> - **418 static analysis findings** triaged (397 Slither + 21 Aderyn). The high finding counts are expected — Moloch's heavy use of assembly, governance-gated delegatecall, and `payable` gas optimizations trigger many heuristic detectors. All HIGH/MEDIUM findings were investigated and resolved as false positives or intentional design patterns.
> - **9 risk patterns** evaluated against all external-facing functions.
> - **11 Solodit queries** cross-referenced against real-world exploits.
> - **8 suspicious spots** investigated in ATTACK phase. After devil's advocate falsification:
>   - **0 novel findings** — all spots falsified or mapped to existing known findings.
>   - 1 duplicate confirmed via Solodit: fee-on-transfer token accounting (KF#8).

---

## Phase 1: SETUP

### Slither Results

| Severity | Count | Key Detectors | Resolution |
|----------|-------|--------------|------------|
| HIGH | 6 | arbitrary-send-eth, controlled-delegatecall, incorrect-shift, unchecked-transfer | Governance-gated execution; correct Yul operand order; co-deployed tokens always revert-or-return-true |
| MEDIUM | 65+ | divide-before-multiply, incorrect-equality, locked-ether, reentrancy-no-eth | `mulDiv` is multiply-first in assembly; equality checks on protocol-internal values; ETH recoverable via ragequit; no external calls in flagged reentrancy paths |
| LOW/INFO | 325+ | calls-loop, timestamp, assembly, naming-convention | Informational — expected for a complex governance contract with inline assembly |

### Slither HIGH Detail

| # | Detector | Lines | Resolution |
|---|----------|-------|------------|
| 1 | `arbitrary-send-eth` | 976-986 | `_execute()` is internal, reachable only via governance proposals or DAO-issued permits. Target and calldata hash-locked via `_intentHashId()`. |
| 2 | `controlled-delegatecall` | 976-986 | Same as above — delegatecall path requires governance approval. |
| 3 | `incorrect-shift` | 1930-1941 | `_ffs()` De Bruijn FFS technique. Yul `shl(shift, value)` operand order is correct. Known heuristic limitation. |
| 4 | `incorrect-shift` | 744-768 | Misattributed — no assembly at cited lines (Solidity-level `buyShares` logic). |
| 5 | `unchecked-transfer` | 706-756 (x2) | Co-deployed `Shares`/`Loot` contracts always return `true` or revert. External `payToken` uses Solady-style `safeTransferFrom`. |

### Aderyn Results

21 findings (10 HIGH, 11 LOW). The HIGH findings overlap with Slither's detectors:

| Detector | Resolution |
|----------|------------|
| delegatecall in loop (H-1) | `multicall` is self-only delegatecall — standard batching pattern |
| abi.encodePacked (H-2) | Used for CREATE2 bytecode construction, not hash key derivation |
| Unprotected initializer (H-3) | `_init` is internal with one-time guard; other flagged functions are internal helpers |
| Unsafe casting (H-4) | Inputs bounded by protocol (`block.number` for uint48, `getPastVotes` for uint96) |
| Incorrect shift (H-5) | Same as Slither — Yul operand order is correct |
| Contract name reused (H-6) | Interface redeclaration across files — compilation concern, not security |
| Uninitialized state (H-7) | Zero-defaults are intentional (`config=0`, `autoFutarchyParam=0`) |
| Unprotected ETH send (H-8) | Constructor `payable` is gas opt; `executeByVotes`/`spendPermit` are governance-gated |
| Unchecked delegatecall (H-9) | Same as Slither — target hash-locked to governance vote |
| Locked ether (H-10) | DAO treasury ETH recoverable via governance proposals and ragequit |

LOW findings (L-1 through L-11): Code style and gas suggestions (public→external, missing indexed events, literal formatting, etc.).

### Solodit Cross-Reference

| Query | Matches | Relevance |
|-------|---------|-----------|
| delegatecall governance | 3 | Not applicable — both paths governance-gated, multicall is self-only |
| fee-on-transfer tokens | 5 | **Applicable** — `buyShares` and `fundFutarchy` assume exact delivery (KF#8) |
| flash loan voting snapshot | 2 | Not applicable — block.number-1 snapshot correctly prevents manipulation |
| selfdestruct force-send ETH | 5 | Known — `address(this).balance` used, economically irrational to exploit |
| unchecked ERC20 USDT | 5 | Not applicable — Solady-style safe transfers handle non-standard returns |
| reentrancy EIP-1153 | 0 | — |
| mulDiv overflow rounding | 5 | Not applicable — floor division favors protocol; inputs bounded |
| ragequit proportional / sale cap / prediction market / DAICO tap | 0 each | No matching prior art in Solodit database |

### Cyfrin Checklist

Relevant categories applied during HUNT:
- Denial-of-Service: withdrawal pattern ✓, minimum amounts ✓, blacklistable tokens (KF#7)
- Reentrancy: CEI pattern ✓, cross-contract callbacks ✓, transient storage guard ✓
- Access Control: privileged functions ✓, function visibility ✓
- Flash Loan: snapshot protection ✓
- Oracle: N/A (no oracles)

---

## Phase 2: MAP

### Components

#### Moloch (Main DAO Contract)
- **Purpose:** DAO governance framework with proposals, voting, timelock, permits, futarchy, token sales, ragequit, and on-chain chat.
- **Key State:** `proposalThreshold`, `quorumBps`, `timelockDelay`, `ragequittable`, `config`, `tallies`, `futarchy`, `sales`, ERC-6909 `balanceOf`/`totalSupply`
- **Roles:** `SUMMONER` (init-only), `onlyDAO` (self-call for all settings), public functions for voting/buying/ragequit
- **External Surface:** 20+ public/external functions

#### Shares / Loot / Badges / Summoner
- **Shares:** ERC-20 voting tokens with checkpoints and split delegation. `onlyDAO` for mint/burn/lock.
- **Loot:** ERC-20 non-voting economic tokens. `onlyDAO` for mint/burn/lock.
- **Badges:** ERC-721 soulbound NFTs for top-256 shareholders. Auto-maintained.
- **Summoner:** CREATE2 factory for deploying Moloch clones.

### Invariants

1. `Shares.totalSupply == Σ balanceOf[user]` (sum invariant, also Loot and ERC-6909)
2. Proposal state machine: Unopened → Active → {Succeeded, Defeated, Expired} → {Queued →} Executed
3. `executed[id]` is a one-way latch
4. Ragequit pro-rata: `due = pool * amt / total` (conservation of value)
5. Futarchy `payoutPerUnit` fixed at resolution, immutable thereafter
6. `config` bump invalidates all pre-bump proposal and permit IDs
7. No admin keys post-init — all settings require governance vote

---

## Phase 3: HUNT

### Suspicious Spots

| # | Spot | Source | Priority |
|---|------|--------|----------|
| 1 | Rounding in ragequit/futarchy | Risk Pattern #4 | Medium |
| 2 | Force-fed ETH in ragequit | Risk Pattern #7 + Solodit | Medium |
| 3 | Cross-contract reentrancy | Risk Pattern #6 + Slither | High |
| 4 | Unchecked token transfer returns | Risk Pattern #9 + Solodit | Medium |
| 5 | Missing slippage in buyShares | Risk Pattern #8 | Low |
| 6 | Proxy storage collisions | Risk Pattern #5 | Low |
| 7 | Fee-on-transfer token accounting | Solodit cross-reference | Medium |
| 8 | Delegatecall governance via multicall | Solodit cross-reference | Medium |

### Risk Patterns Not Applicable

| Pattern | Why N/A |
|---------|---------|
| ERC-4626 Share Inflation | Not a vault — fixed-price sales |
| Oracle Staleness | No oracles — snapshot-based vote weights |
| Flash Loan Entry Points | Block N-1 snapshots — flash loans ineffective |

### Per-Function Assessment

| Function | External Calls | Access | Assessment |
|----------|---------------|--------|-----------|
| `openProposal()` | None | Public (threshold-gated) | Safe ✓ |
| `castVote()` | None | Public (shareholder) | Safe ✓ |
| `cancelVote()` / `cancelProposal()` | None | Voter / proposer | Safe ✓ |
| `queue()` | None | Public (state-gated) | Safe ✓ |
| `fundFutarchy()` | safeTransferFrom | Public | FoT accounting (KF#8) |
| `resolveFutarchyNo()` | None | Public (state-gated) | Safe ✓ |
| `setPermit()` / `setSale()` / `setAllowance()` | None | onlyDAO | Safe ✓ |
| `multicall()` | self-delegatecall | Public | Safe ✓ |

---

## Phase 4: ATTACK

### #1: Rounding Direction in Ragequit/Futarchy

`mulDiv(pool, amt, total)` at L1987 performs `div(mul(x, y), d)` — floor division. Ragequit and futarchy payouts round down (protocol-favorable). `buyShares` uses exact multiplication.

**Solodit cross-ref:** "Premia calculation can cause DOS" — not applicable, inputs bounded by uint96 supplies.

**Verdict: NO VULNERABILITY.** Rounding consistently favors the DAO.

### #2: Force-Fed ETH in Ragequit

`ragequit()` L790 uses `address(this).balance`. Force-fed ETH inflates the pool, but the attacker permanently loses the donated ETH while all ragequitters benefit proportionally. Post-Dencun (EIP-6780), `SELFDESTRUCT` only sends ETH during same-transaction creation.

**Solodit cross-ref:** "Artificial asset balance inflation" — confirms pattern, economic analysis shows cost > benefit.

**Verdict: NO VULNERABILITY.** Economically irrational.

### #3: Cross-Contract Reentrancy

All external call sites use `nonReentrant` (EIP-1153 transient storage) and follow CEI:
- `buyShares()` L735: cap updated before ETH refund ✓
- `ragequit()` L794: burns before payouts ✓
- `executeByVotes()` L521: `executed[id] = true` before `_execute` ✓
- `spendPermit()` L672: `_burn6909` before `_execute` ✓
- `cashOutFutarchy()` L602: `_burn6909` before `_payout` ✓

Shares/Loot `_moveTokens` makes zero external calls (Slither `reentrancy-no-eth` is a false positive — only internal storage writes).

**Verdict: NO VULNERABILITY.** Comprehensive reentrancy protection.

### #4: Unchecked Token Transfer Returns

`safeTransfer`/`safeTransferFrom` (L2019-2052) use Solady-style assembly that handles: standard returns, USDT no-return-value, non-contract addresses, and failed calls.

**Solodit cross-ref:** 5 USDT-related findings — Moloch already handles this correctly.
**Cyfrin checklist SOL-AM-DOSA-3:** Blacklistable tokens can DoS ragequit (KF#7, known).

**Verdict: NO VULNERABILITY.** Safe transfer handles all edge cases.

### #5: Missing Slippage in buyShares

`buyShares()` L706: `if (maxPay != 0 && cost > maxPay) revert NotOk()`. Price is governance-set (deterministic), not AMM-computed.

**Verdict: NO VULNERABILITY.** Slippage protection present.

### #6: Proxy Storage Collisions

EIP-1167 minimal clones with immutable implementation. No upgrade mechanism.

**Verdict: NO VULNERABILITY.** Non-upgradeable.

### #7: Fee-on-Transfer Token Accounting

`buyShares()` L739 and `fundFutarchy()` L565 use `safeTransferFrom` and credit the requested amount without checking actual receipt. With FoT tokens, the contract receives less than credited.

**Mitigating factors:** `setSale` is `onlyDAO` — governance controls accepted tokens. Futarchy `rewardToken` is restricted to ETH/shares/loot — FoT tokens cannot be set through the standard path.

**Solodit evidence:** Multiple Medium findings for FoT accounting.

**Verdict: DUPLICATE (KF#8).** Known finding, governance-mitigated.

### #8: Delegatecall via Multicall

`multicall()` L893 uses `address(this).delegatecall(data[i])` — target hardcoded to self. Standard batching pattern. Cannot delegatecall to external contracts.

**Solodit cross-ref:** "Arbitrary delegatecall within SubProxy" — not applicable, self-only.

**Verdict: NO VULNERABILITY.** Standard multicall pattern.

---

## Findings Summary

| # | Spot | Verdict | Key Evidence |
|---|------|---------|-------------|
| 1 | Rounding | NO VULN | Floor division favors protocol |
| 2 | Force-fed ETH | NO VULN | Economically irrational |
| 3 | Reentrancy | NO VULN | EIP-1153 guard + CEI on all paths |
| 4 | Unchecked transfers | NO VULN | Solady-style safe transfers |
| 5 | Slippage | NO VULN | `maxPay` + deterministic pricing |
| 6 | Proxy collisions | NO VULN | Non-upgradeable clones |
| 7 | **FoT accounting** | **DUPLICATE (KF#8)** | Governance-mitigated |
| 8 | Delegatecall multicall | NO VULN | Self-only, standard pattern |

### Static Analysis

| Tool | Findings | True Positives |
|------|----------|----------------|
| Slither | 397 (6 HIGH, 65+ MEDIUM, 325+ LOW/INFO) | 0 |
| Aderyn | 21 (10 HIGH, 11 LOW) | 0 |

The zero true-positive rate reflects the codebase's security posture rather than tool limitations — Moloch's architecture (governance-gated execution, EIP-1153 reentrancy guards, Solady-style assembly, non-upgradeable clones) is specifically designed to avoid the vulnerability classes these detectors target.

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 0 (1 duplicate: KF#8) |
| Low | 0 |
| Informational | 0 |

**Zero novel findings.** The Map-Hunt-Attack methodology with full MCP integration (Slither + Aderyn + Solodit + Cyfrin checklist) investigated 8 suspicious spots and resolved all via the devil's advocate protocol. The Solodit cross-reference added value by surfacing the FoT token pattern (KF#8) that pure static analysis missed. Strong security properties confirmed across reentrancy, access control, arithmetic, token safety, and proxy architecture.

---

> Audit performed using [Archethect SC-Auditor v0.3.0](https://github.com/Archethect/sc-auditor) with MCP tools: Slither v0.11.5, Aderyn v0.1.9, Solodit search, Cyfrin audit checklist. Cross-referenced against 22 prior audit reports.
