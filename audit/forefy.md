# Forefy Smart Contract Audit — Moloch.sol

**Skill:** [forefy/.context](https://github.com/forefy/.context) (`smart-contract-audit`)
**Type:** Multi-expert security audit with knowledge base cross-referencing
**Target:** `src/Moloch.sol` (2110 lines, 5 contracts: Moloch, Shares, Loot, Badges, Summoner)
**Date:** 2026-03-11
**Methodology:** Forefy 3-round multi-expert framework (Expert 1: systematic, Expert 2: economic/integration, Expert 3: triager validation) with fv-sol-X knowledge base and governance protocol context

---

## Audit Configuration

**Blockchain:** Ethereum/EVM (Solidity ^0.8.30)
**Protocol type:** Governance/DAO (on-chain voting, treasury management, token sales, ragequit)
**Protocol context file:** `reference/solidity/protocols/governance.md`
**Solidity checks applied:** Governance/DAO tricks + 10 fv-sol categories

### Knowledge Base References Loaded

| KB Reference | Relevance |
|---|---|
| `fv-sol-1` Reentrancy (c9: transient storage) | EIP-1153 nonReentrant modifier |
| `fv-sol-2` Precision Errors (c6: ERC4626, c7: special tokens) | mulDiv, share/loot math, fee-on-transfer |
| `fv-sol-3` Arithmetic Errors (c5: assembly) | Assembly mulDiv, unchecked blocks |
| `fv-sol-4` Access Control (c9: CREATE2 squatting) | Summoner factory, onlyDAO, permits |
| `fv-sol-5` Logic Errors (c6: same-block snapshot, c7: msg.value multicall, c8: force ETH) | Snapshot at N-1, multicall, ragequit balance |
| `fv-sol-6` Unchecked Returns (c8: return bomb, c10: nonstandard ERC20) | _execute, safeTransfer |
| `fv-sol-8` Slippage | buyShares maxPay parameter |
| `fv-sol-9` Unbounded Loops (c6: blacklistable tokens, c7: gas griefing) | Ragequit token loop |
| `fv-sol-10` Oracle Manipulation | N/A (no oracle dependency) |
| `governance.md` protocol context | 8 governance-specific bug classes |

---

## Round 1: Security Expert 1 — Systematic Code Review

### Scope Analysis

- **Core protocol:** Moloch (governance, voting, execution, futarchy, permits, sales, ragequit)
- **Token contracts:** Shares (ERC-20 Votes), Loot (ERC-20), Badges (ERC-721 SBT)
- **Factory:** Summoner (EIP-1167 CREATE2 minimal clones)
- **Utilities:** mulDiv (assembly), safeTransfer/safeTransferFrom/safeTransferETH (assembly)

### Highest-Risk Function Analysis

**1. Reentrancy (fv-sol-1)**

- `nonReentrant` modifier at line 1003-1015 uses EIP-1153 transient storage (`TSTORE`/`TLOAD`)
- Guard is set before execution and cleared after — both success and revert paths covered
- Applied to: `executeByVotes`, `spendPermit`, `buyShares`, `ragequit`, `cashOutFutarchy`, `spendAllowance`
- Cross-referenced fv-sol-1-c9: transient mutex not cleared DoS — **guard IS cleared** at line 1013 (`tstore(REENTRANCY_GUARD_SLOT, 0)`) in the post-execution assembly block. No DoS vector.
- `multicall` (line 893) uses `delegatecall`, which inherits the caller's context including transient storage. If any sub-call sets the reentrancy guard, subsequent sub-calls that need `nonReentrant` would fail. However, `multicall` is NOT `payable` and NOT `nonReentrant` itself — sub-calls to `nonReentrant` functions work correctly because each enters/exits the guard independently within the same `delegatecall` context.

> **Review:** Reentrancy protection is sound. EIP-1153 guard is correctly implemented with cleanup in all exit paths. No fv-sol-1-c9 DoS vector — the guard is explicitly cleared.

**2. Flash Loan Vote Manipulation (governance.md: Flash Loan Vote Manipulation)**

- `castVote` at line 369: `uint96 weight = uint96(shares.getPastVotes(msg.sender, snap))`
- `snap` = `snapshotBlock[id]` = `block.number - 1` (set in `openProposal` at line 290)
- This uses **prior-block** snapshot, not current balance — immune to same-block flash loan manipulation
- Cross-referenced fv-sol-5-c6: Same-block snapshot abuse — **false positive** by design. Snapshot at N-1 means flash-loaned tokens deposited at block N have zero voting power.

> **Review:** Immune to flash loan vote manipulation. `getPastVotes(msg.sender, block.number - 1)` is the gold-standard pattern per both fv-sol-5-c6 false positive criteria and governance.md remediation notes.

**3. Voting Checkpoint Overwrite (governance.md: Voting Checkpoint Overwrite)**

- Shares contract uses ERC20Votes-style checkpoints (standard Solady/OZ pattern)
- No custom `_writeCheckpoint` modification found — uses upstream implementation
- Per governance.md false positive: "unmodified, well-tested upstream library"

> **Review:** No checkpoint overwrite vulnerability. Standard ERC20Votes implementation.

**4. Quorum and Threshold via Live Supply (governance.md)**

- `state()` at line 468: `mulDiv(uint256(bps), ts, 10000)` where `ts = supplySnapshot[id]`
- Supply is snapshotted at proposal creation (line 296: `supplySnapshot[id] = supply`)
- Per governance.md false positive: supply is checkpointed, not live — **not vulnerable**
- `proposalThreshold` check at line 285 uses current votes (`getVotes`), not past — this is intentional per code comment at line 346: "threshold uses current votes by design"

> **Review:** Quorum uses snapshotted supply. Threshold uses current votes intentionally — this allows threshold to reflect current stake without enabling flash loan voting (since voting power itself uses past snapshot).

**5. msg.value Reuse in Multicall (fv-sol-5-c7)**

- `multicall` at line 893-904 uses `delegatecall` — each sub-call sees the same `msg.value`
- However, `multicall` is **NOT `payable`** — `msg.value` is always 0
- Per fv-sol-5-c7 false positive: "Function is nonpayable — msg.value always 0"

> **Review:** Immune to msg.value reuse. multicall is not payable, invalidating the entire attack class.

**6. Force ETH Injection (fv-sol-5-c8)**

- `ragequit` at line 790: `pool = tk == address(0) ? address(this).balance : balanceOfThis(tk)`
- Uses `address(this).balance` directly for ETH — vulnerable to `selfdestruct` force-feeding
- However, force-fed ETH benefits ragequitters (larger pro-rata share), not the attacker
- Per fv-sol-5-c8 false positive: "Contract explicitly designed to accept arbitrary ETH"

> **Review:** Force-fed ETH inflates ragequit payouts. Economically irrational attack — attacker donates ETH to benefit others. Not exploitable. (Duplicate: QuillShield DGA-2)

**7. Assembly mulDiv (fv-sol-3-c5)**

- Custom assembly mulDiv implementation — multiply-first to avoid precision loss
- Uses `mul`/`div` with overflow handling via `mulmod` check
- Solidity 0.8.30 with assembly blocks uses unchecked arithmetic — but the implementation includes explicit overflow checks

> **Review:** mulDiv implementation follows standard assembly pattern with overflow protection. No fv-sol-3-c5 vulnerability.

**8. Unchecked Returns / Nonstandard ERC20 (fv-sol-6-c10)**

- `safeTransfer` and `safeTransferFrom` at lines ~2060-2110 use Solady-style assembly
- Assembly checks `returndatasize()` and validates return value — handles USDT (no return), BNB, etc.
- Per fv-sol-6-c10: "SafeERC20 usage" — equivalent protection via assembly

> **Review:** Token transfer safety is handled correctly via Solady-style assembly safe transfers. Covers nonstandard ERC20 behavior.

**9. Return Data Bomb (fv-sol-6-c8)**

- `_execute` at line 976-986: `(ok, retData) = to.call{value: value}(data)` — returndata is ABI-decoded into `bytes memory retData`
- If governance executes against a malicious contract, large returndata could consume gas via memory expansion
- However, execution targets must pass a governance vote — governance-gated

> **Review:** Theoretical gas concern on governance-gated function. Not exploitable by unprivileged users. (Duplicate: SCV Scan #3, QuillShield ECS-3)

**10. Blacklistable Token DoS in Ragequit (fv-sol-9-c6)**

- `ragequit` iterates over caller-supplied `tokens` array, calling `_payout` for each
- If a token (e.g., USDT) blacklists the DAO address, `safeTransfer` reverts
- Caller controls the token array and can omit problematic tokens
- Per fv-sol-9-c6: push-model where caller can avoid the blacklisted token

> **Review:** Caller-controlled mitigation. Omit blacklisted token from array. (Duplicate: Pashov #9, SCV Scan #1, QuillShield ECS-1)

--- END OF EXPERT 1 ANALYSIS ---

## Round 2: Security Expert 2 — Economic & Integration Focus

### Independent Protocol Analysis

**1. Futarchy Economic Attack Vectors**

**1a. Earmark Double-Commitment (Economic Manipulation)**

When `autoFutarchyParam` is set with non-minted reward tokens (shares or loot held by DAO), the earmark at `openProposal` line 336 (`F.pool += amt`) is a soft accounting entry — no actual token transfer or lock occurs. Multiple concurrent proposals earmark the same balance.

- **Attack path:** Create N proposals, each earmarking the DAO's full share/loot balance. Only the first to resolve can actually pay out; later ones silently fail or under-deliver.
- **Impact:** Futarchy incentive under-delivery for later proposals.
- **Mitigation:** Use minted Loot rewards (`rewardToken = 0` → minted via address(1007)), which have no balance constraint. Documented in configuration guidance.

> **Review:** Valid economic concern, configuration-dependent. (Duplicate: Octane #9, Pashov #3, QuillShield SID-1)

**1b. Vote Receipt Transferability and cancelVote**

ERC-6909 vote receipts are transferable (lines 915-937) unless they are permit receipts (SBT check at line 916). A voter who transfers their receipt to another address cannot `cancelVote` because `_burn6909` will underflow on their zero balance.

- **Impact:** Voluntary degradation of cancel-vote UX. Does not affect vote integrity.
- **Economic analysis:** No profit incentive. User opts in to transferring receipts.

> **Review:** Valid observation, voluntary user action. (Duplicate: Pashov #6)

**2. Governance Parameter Manipulation (governance.md)**

All settings functions are `onlyDAO` (line 22-24: `msg.sender == address(this)`). No external admin, owner, or multisig controls exist. Parameters can only change via a full governance proposal-vote-execute cycle.

- Cross-referenced governance.md: "Governance Parameter Manipulation and Veto Loss" — false positive when "all parameter changes require a full governance proposal"
- No vetoer role exists to lose — governance is purely democratic
- `bumpConfig()` invalidates all in-flight proposals — this is by design as an emergency mechanism

> **Review:** No centralization risk. Pure self-governance model eliminates the admin manipulation attack class entirely.

**3. Delegation State Corruption (governance.md)**

- Shares uses standard ERC20Votes from Solady — delegation is inherited, not custom
- No custom delegation logic — standard `delegate()` and `_moveDelegateVotes()`
- Per governance.md false positive: "unmodified, well-tested upstream library"

> **Review:** Standard delegation implementation. No corruption vector.

**4. CREATE2 Salt and Factory Security (fv-sol-4-c9)**

- Summoner factory deploys via EIP-1167 minimal clones with CREATE2
- Salt is `bytes32(bytes20(address(this)))` — derived from the Moloch contract address itself
- `init()` requires `msg.sender == SUMMONER` where `SUMMONER = msg.sender` (set in constructor)
- CREATE2 address can be predicted, but `init()` is permissioned to the Summoner only

> **Review:** CREATE2 squatting is mitigated by the SUMMONER permission check. Pre-deployed code at the CREATE2 address would need to impersonate the Summoner factory.

**5. Permit System Security (fv-sol-4)**

- `setPermit` is `onlyDAO` — permits can only be created via governance
- `spendPermit` burns 1 ERC-6909 token from `msg.sender` and executes
- Permit receipts are marked SBT (`isPermitReceipt[tokenId] = true`) — non-transferable (lines 916, 929)
- Each spend burns a token, providing per-use authorization

> **Review:** Permit system is well-designed. SBT marking prevents unauthorized transfer. Per-use burn prevents replay.

**6. Sale Cap Sentinel (fv-sol-5-c2: Incorrect Conditionals)**

- `buyShares` line 716: `if (cap != 0 && shareAmount > cap) revert NotOk()`
- Line 726: `s.cap = cap - shareAmount` — when cap reaches 0, future checks treat it as "unlimited"
- Sentinel collision: `0` means both "unlimited" and "exhausted"

> **Review:** Known logic quirk. (Duplicate: Zellic #13, Plainshift #1)

### Oversight Analysis of Expert 1

Expert 1's analysis is thorough. I concur with all findings and false positive determinations. One area I would emphasize more strongly:

- **init() quorumBps validation gap** (line 226): `if (_quorumBps != 0) quorumBps = _quorumBps` — no range validation. `setQuorumBps` at line 814 validates `bps > 10_000`, but `init()` does not. This is a configuration-time concern, not a runtime vulnerability.

> **Review:** Valid hardening item. (Duplicate: Trail of Bits #2.1, QuillShield IAS-1)

--- END OF EXPERT 2 ANALYSIS ---

## Round 3: Triager Validation (Budget Protection)

### Triager Mandate

Approach each finding as a budget-protecting skeptic. Default stance: protect the bounty budget. Only pay for undeniably valid, exploitable vulnerabilities.

---

### Cross-Reference Validation

All findings from Experts 1 and 2 have been cross-referenced against:
- 10 fv-sol vulnerability categories with sub-classifications
- 8 governance-specific bug classes from `protocols/governance.md`
- Governance/DAO-specific audit tricks
- 10 prior audit reports (Zellic, Plainshift, Octane, Pashov, Trail of Bits, Cyfrin, SCV Scan, QuillShield, Archethect, HackenProof)

### Finding-by-Finding Triager Validation

**Spot 1: Futarchy Earmark Double-Commit**

- **Technical Disproof Attempt:** Searched for any locking mechanism in `openProposal` that prevents double-earmarking. None found — `F.pool += amt` is a pure accounting entry.
- **Economic Disproof Attempt:** Attack requires creating multiple proposals simultaneously. With `proposalThreshold > 0`, attacker needs real stake. With minted Loot rewards, there is no balance constraint to exhaust. Only non-minted reward tokens (shares/loot held by DAO) are affected.
- **Verdict:** QUESTIONABLE — Valid concern but configuration-dependent. Use minted rewards to eliminate.
- **Bounty Assessment:** $0 — mitigable via documented configuration (minted Loot rewards). Not a code vulnerability.

**Spot 2: Vote Receipt Transfer Breaks cancelVote**

- **Technical Disproof Attempt:** `cancelVote` calls `_burn6909(msg.sender, rid, weight)` — will underflow if receipts were transferred away. Confirmed technically valid.
- **Economic Disproof Attempt:** User voluntarily transfers their receipt. No attacker profit. Vote outcome unaffected.
- **Verdict:** DISMISSED — Voluntary user action with no exploit path. cancelVote is a convenience, not a security guarantee.
- **Bounty Assessment:** $0 — No exploitation scenario exists.

**Spot 3: Sale Cap Sentinel Collision**

- **Technical Disproof Attempt:** Requires exact exhaustion of cap. After exhaustion, `cap == 0` bypasses the cap check. New shares can be minted/transferred beyond original cap.
- **Economic Disproof Attempt:** DAO governance can reconfigure sales at any time. Requires exact sell-out edge case. Governance retains full control.
- **Verdict:** QUESTIONABLE — Real but narrow edge case. Governance can mitigate.
- **Bounty Assessment:** $100-200 — Low severity logic quirk with governance override available.

**Spot 4: init() Missing quorumBps Validation**

- **Technical Disproof Attempt:** Only callable by SUMMONER factory during deployment. Subsequent changes via `setQuorumBps` validate correctly.
- **Economic Disproof Attempt:** Privileged-only initialization. No unprivileged exploitation path.
- **Verdict:** DISMISSED — Admin-only configuration path. Not exploitable post-deployment.
- **Bounty Assessment:** $0 — Informational hardening suggestion only.

**Spot 5: Blacklistable Token Ragequit DoS**

- **Technical Disproof Attempt:** Caller supplies token array. Omitting the blacklisted token recovers all other assets.
- **Verdict:** DISMISSED — User-controlled mitigation exists.
- **Bounty Assessment:** $0 — Known ERC20 interaction pattern, not a protocol vulnerability.

**Spot 6: Return Data Bomb on Governance Execution**

- **Technical Disproof Attempt:** Execution target must pass a full governance vote. Gas cost borne by voluntary executor.
- **Verdict:** DISMISSED — Governance-gated. Not exploitable by unprivileged users.
- **Bounty Assessment:** $0 — Informational only.

**Spot 7: Force-fed ETH in Ragequit**

- **Technical Disproof Attempt:** Force-fed ETH increases `address(this).balance`, inflating ragequit payouts for ALL members. Attacker loses their ETH.
- **Verdict:** DISMISSED — Economically irrational. Attacker subsidizes victims.
- **Bounty Assessment:** $0

**Spot 8: Permissionless Proposal Opening DoS**

- **Technical Disproof Attempt:** When `proposalThreshold = 0`, `castVote` auto-opens proposals via `openProposal`. The opener becomes `proposerOf[id]` and can call `cancelProposal`. However, `cancelProposal` (line 425) requires `(t.forVotes | t.againstVotes | t.abstainVotes) != 0` — it requires ZERO votes. Since the opener just voted, this condition fails. The proposal cannot be cancelled.
- **Re-analysis:** Wait — `castVote` first opens the proposal (setting `proposerOf[id] = msg.sender`), then records the vote. After `castVote`, the tally is non-zero. So `cancelProposal` requires zero tally, which is impossible after the auto-open+vote atomic operation. The original proposer can't cancel either, because they're no longer `proposerOf[id]`.
- **Verdict:** VALID observation — front-runner steals proposer role, but cannot cancel (tally is non-zero). Real impact: original proposer loses cancel ability. But cancel was already very restricted (requires zero votes).
- **Bounty Assessment:** $50-100 — Low impact, mitigable by `proposalThreshold > 0`.

---

## Findings Summary

### Severity Formula Applied

```
SEVERITY = Impact × Likelihood × Exploitability → Base Score → Conservative Adjustment (round DOWN)
```

After applying the conservative severity calibration framework and triager validation:

| # | Finding | Forefy Severity | Confidence | Triager Verdict | Prior Duplicates |
|---|---------|----------------|------------|-----------------|------------------|
| 1 | Futarchy earmark double-commits non-minted tokens | Low | Medium | QUESTIONABLE | Octane #9, Pashov #3, QuillShield SID-1 |
| 2 | Vote receipt transferability degrades cancelVote | Low | High | DISMISSED | Pashov #6 |
| 3 | Sale cap sentinel collision (0 = unlimited = exhausted) | Low | High | QUESTIONABLE | Zellic #13, Plainshift #1 |
| 4 | init() missing quorumBps range validation | Low | High | DISMISSED | Trail of Bits #2.1, QuillShield IAS-1 |
| 5 | Blacklistable token ragequit DoS | Low | High | DISMISSED | Pashov #9, SCV Scan #1, QuillShield ECS-1 |
| 6 | Return data bomb on governance execution | Low | Medium | DISMISSED | SCV Scan #3, QuillShield ECS-3 |
| 7 | Force-fed ETH in ragequit payouts | Low | High | DISMISSED | QuillShield DGA-2 |
| 8 | Permissionless proposal opening front-run | Low | Medium | VALID (Low) | Octane #1, Pashov #8 |

**Total: 0 Critical, 0 High, 0 Medium, 8 Low**
**Triager verdict: 1 VALID (Low), 2 QUESTIONABLE, 5 DISMISSED**

---

## Governance Protocol Context — Bug Class Coverage

| governance.md Bug Class | Result |
|---|---|
| Voting Checkpoint Overwrite | Not vulnerable (standard ERC20Votes) |
| Flash Loan Vote Manipulation | Not vulnerable (snapshot at N-1) |
| Delegation State Corruption | Not vulnerable (standard delegation) |
| Voting Power Accounting Desync | Not vulnerable (no separate accumulator) |
| Quorum/Threshold via Live Supply | Not vulnerable (snapshotted supply) |
| Proposal Threshold Bypass via Sigs | N/A (no signature-based proposals) |
| Delegation Griefing via MAX_DELEGATES | N/A (no delegate count limits) |
| Unbounded Lock Duration | N/A (no staking/locking) |
| Governance Parameter Manipulation | Not vulnerable (onlyDAO, no admin keys) |
| Flash-Loan Proxy Upgrade Hijack | Not vulnerable (N-1 snapshot + no proxy upgrade) |

**10/10 governance bug classes evaluated. 0 vulnerabilities found.**

## fv-sol Knowledge Base Coverage

| fv-sol Category | Sub-checks Applied | Result |
|---|---|---|
| fv-sol-1 Reentrancy | c1-c9 (incl. transient storage c9) | Clean — EIP-1153 guard correctly implemented |
| fv-sol-2 Precision | c1-c7 (incl. ERC4626, special tokens) | Clean — mulDiv correct, no ERC4626 |
| fv-sol-3 Arithmetic | c1-c6 (incl. assembly arithmetic) | Clean — assembly mulDiv has overflow checks |
| fv-sol-4 Access Control | c1-c11 (incl. CREATE2, signatures) | Clean — onlyDAO, SUMMONER checks |
| fv-sol-5 Logic Errors | c1-c11 (incl. same-block, msg.value, force ETH) | 3 low findings (all duplicates) |
| fv-sol-6 Unchecked Returns | c1-c11 (incl. return bomb, nonstandard ERC20) | 1 low finding (return bomb, duplicate) |
| fv-sol-7 Proxy | c1+ | N/A — no upgradeable proxy pattern |
| fv-sol-8 Slippage | c1-c6 | Clean — buyShares has maxPay parameter |
| fv-sol-9 Unbounded Loops | c1-c8 (incl. blacklistable tokens) | 1 low finding (blacklistable DoS, duplicate) |
| fv-sol-10 Oracle | c1-c7 | N/A — no oracle dependency |

---

## Executive Summary

### Security Posture Assessment

**Overall Risk Level:** Low
**Critical Findings:** 0
**Total Findings:** 8 (all Low), of which 5 dismissed, 2 questionable, 1 valid

### Key Risk Areas

1. **Configuration-dependent concerns:** Futarchy earmark double-commit and permissionless proposal DoS are both mitigable via documented configuration guidance (minted rewards, proposalThreshold > 0)
2. **Token compatibility edge cases:** Blacklistable tokens in ragequit (caller-controlled mitigation), fee-on-transfer tokens in sales (DAO-configured)
3. **All findings are duplicates** of issues already identified in prior audits

### Novel Findings

**Zero.** All 8 findings have been independently identified by 2-4 prior auditors. The Forefy framework's governance protocol context and fv-sol knowledge base provide strong coverage but did not surface any vulnerability missed by the prior 10 audits.

### What the Framework Got Right

The three-layer reading order (governance protocol context → fv-sol deep theory → Solidity tricks) is well-structured for governance audits. The governance.md protocol context file covers the most important governance-specific attack classes, and the false positive criteria are precise enough to correctly identify Moloch's defenses:
- Snapshot at N-1 → immune to flash loan voting
- Standard ERC20Votes → immune to checkpoint overwrite
- Snapshotted supply → immune to quorum manipulation
- onlyDAO → immune to parameter manipulation

The conservative severity calibration (round DOWN on borderline) and triager budget-protection role both worked as intended, preventing severity inflation.

---

## HackenProof Triage Backtrack

Since all 8 findings are duplicates of issues already triaged in the HackenProof report, no new triage entries are needed. The existing HackenProof severity classifications apply:

| Forefy Finding | HackenProof Triage Severity |
|---|---|
| #1 Futarchy earmark double-commit | Medium (HackenProof #3) |
| #2 Vote receipt transferability | Low (HackenProof #4) |
| #3 Sale cap sentinel | Low (HackenProof #1) |
| #4 init() quorumBps | Low (HackenProof #6) |
| #5 Blacklistable token DoS | Low (HackenProof #7) |
| #6 Return data bomb | Out of Scope (HackenProof #12) |
| #7 Force-fed ETH | Out of Scope (HackenProof #14) |
| #8 Permissionless proposal DoS | Medium (HackenProof #8) |

**No changes to the HackenProof triage report are required.** All Forefy findings map cleanly to existing triaged entries.
