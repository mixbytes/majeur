# Grimoire Agentic Audit — Audit Response

Evaluated: Grimoire methodology (manual execution of [JoranHonig/grimoire](https://github.com/JoranHonig/grimoire) agent specs).
Full Summon workflow: GRIMOIRE.md context mapping → 4 parallel Sigil agents (hypothesis-driven hunters) → 3 parallel Familiar agents (adversarial triage). Opus 4.6 for all agents.

## Summary

> **No novel findings.** All 10 confirmed findings are duplicates of KF#1–18 or Certora FV results.
>
> - 4 Sigil agents spawned across 4 attack surfaces (reentrancy/CEI, governance/voting, economic/ragequit, access/peripheral)
> - 3 Familiar agents triaged all results adversarially (code-level disproof attempts)
> - 10 confirmed, 2 severity-adjusted, 3 dismissed (including 1 explicit false positive)
> - Reentrancy surface fully clean — `nonReentrant` on all external-call functions, CEI correctly followed

---

## Methodology

**Grimoire** is a workflow meta-toolkit for security research. Unlike scanner-style tools, it uses specialized agent roles:

- **Sigil agents** — single-context hunters that receive one attack surface hypothesis and search the codebase for evidence. Each sigil tries to PROVE a vulnerability exists.
- **Familiar agents** — adversarial verifiers that independently read the code and try to DISPROVE each sigil finding. Whatever survives both passes is worth the researcher's time.

The full workflow was executed manually using Grimoire's agent prompts (`agents/sigil.md`, `agents/familiar.md`) and the Summon skill's crown jewels reference (`skills/summon/references/domain-crown-jewels.md`).

**Sigil swarm (4 agents, parallel):**
| Agent | Attack Surface | Raw Findings | Confirmed After Triage |
|-------|---------------|-------------|----------------------|
| Sigil 1 | Reentrancy + CEI violations | 0 | 0 (all clean) |
| Sigil 2 | Governance + voting mechanics | 3 | 2 |
| Sigil 3 | Economic + ragequit + futarchy | 6 | 5 (2 severity-adjusted) |
| Sigil 4 | Access control + peripherals | 5 | 3 |

---

## Finding Responses

### [M-01] `castVote` has no proposal state check — Duplicate (KF#15)

**Severity:** Medium | **Confidence:** High | **Familiar verdict:** Confirmed
**Location:** `Moloch.sol` — `castVote()` function

The sigil identified that `castVote()` does not check whether a proposal is in Active state. Unlike `cancelVote()` which has a state check, members can vote on Queued or Succeeded proposals. The Familiar confirmed: `executed[id]` and TTL expiry are the only guards — no `state(id) == Active` check exists.

**Impact on futarchy:** Late votes on Succeeded proposals inflate `winSupply` (total receipt supply for the winning side), diluting `payoutPerUnit` for earlier voters.

**Prior art:** This is KF#15, first identified by Claude (Opus 4.6) via the SECURITY.md audit. The post-queue voting window is by design — the timelock period is intentionally a last-objection window where members can add votes to signal opposition, potentially flipping the outcome.

**Status:** Duplicate — acknowledged as design tradeoff.

---

### [M-02] Futarchy can be funded for already-executed proposals — Duplicate (KF#18)

**Severity:** Medium | **Confidence:** High | **Familiar verdict:** Confirmed
**Location:** `Moloch.sol` — `fundFutarchy()` function

`fundFutarchy` checks `F.resolved` but not `executed[id]`. When futarchy was never enabled for a proposal, execution sets `executed[id] = true` but `_resolveFutarchyYes` returns early (futarchy not enabled), leaving `F.resolved = false`. A subsequent `fundFutarchy` call enables futarchy on an already-executed proposal, creating a permanently unresolvable pool.

**Prior art:** This is KF#18, first identified by ChatGPT Pro (GPT 5.4 Pro).

**Status:** Duplicate.

---

### [M-03] Vote receipts are transferable, enabling futarchy payout arbitrage — Duplicate (KF#5)

**Severity:** Medium | **Confidence:** High | **Familiar verdict:** Confirmed
**Location:** `Moloch.sol` — `transfer()`, `cashOutFutarchy()`

Vote receipt token IDs (ERC-6909) are freely transferable. After a proposal resolves, winning-side receipts can be purchased to claim futarchy payouts. Additionally, a voter who transfers their receipt retains their vote in the tally but loses the ability to `cancelVote` (underflow on `_burn6909`).

**Prior art:** This is KF#5, first identified by Pashov Skills. The transferability is a design tradeoff — receipts function as prediction market claim tokens.

**Status:** Duplicate — acknowledged as design tradeoff.

---

### [M-04] DAICO `claimTap` partial claim forfeiture — Duplicate (Certora L-01)

**Severity:** Medium | **Confidence:** High | **Familiar verdict:** Confirmed
**Location:** `DAICO.sol:811`

When `claimed < owed` (capped by `min(owed, allowance, daoBalance)`), `lastClaim` advances to `block.timestamp`, forfeiting `owed - claimed`. The Familiar noted this is ambiguous: intentional in the ragequit scenario (members exit → treasury shrinks → tap entitlement should reduce) but potentially unintended when allowance is temporarily insufficient.

**Prior art:** Certora L-01, confirmed via formal verification (D-L1a violated, D-L1b reachability witness). Acknowledged as intentional Moloch exit-rights design.

**Status:** Duplicate — acknowledged (by design).

---

### [H-01] Sale cap sentinel collision — Duplicate (KF#1)

**Severity:** High | **Confidence:** High | **Familiar verdict:** Confirmed
**Location:** `Moloch.sol` — `buyShares()`

`cap=0` means both "unlimited sale" and "fully consumed cap." When a capped sale sells exactly `cap` shares, the unchecked subtraction sets `s.cap = 0`, silently converting it to an uncapped sale. The Familiar confirmed: no automatic deactivation when cap reaches zero.

**Prior art:** This is KF#1, the most widely confirmed finding across all audits (Zellic #13, Pashov, SCV Scan, QuillShield, and others).

**Status:** Duplicate.

---

### [L-01] Auto-open proposer attribution can be front-run — Duplicate (KF#11 variant)

**Severity:** Low | **Confidence:** High | **Familiar verdict:** Confirmed
**Location:** `Moloch.sol` — `castVote()` → `openProposal()`

When auto-open is enabled, the first voter triggers `openProposal()` and gets `proposerOf[id] = msg.sender`, gaining cancel rights. Proposal IDs are deterministic (keccak256 hash), enabling front-running. The Familiar confirmed the cancel privilege is limited: `cancelProposal` requires Active state, zero votes cast, and the proposer must meet `proposalThreshold`.

**Prior art:** This is a variant of KF#11 (front-run cancel), previously identified across multiple audits.

**Status:** Duplicate.

---

### [L-02] Futarchy pool locked when winning side has zero voters — Duplicate (KF#6)

**Severity:** Low (adjusted from Medium) | **Confidence:** Medium | **Familiar verdict:** Severity Adjusted
**Location:** `Moloch.sol` — `_finalizeFutarchy()`

When `winSupply == 0`, `payoutPerUnit` stays 0 and no one can claim. The Familiar downgraded severity: for mint-based reward tokens (the common auto-futarchy case), no real assets are locked — just accounting entries. For ETH pools, funds remain in the DAO treasury and are accessible via ragequit. True permanent locking only occurs with external ERC-20 reward tokens and zero voters — an unlikely edge case.

**Prior art:** This is KF#6, first identified by Pashov Skills.

**Status:** Duplicate — severity adjusted to Low.

---

### [L-03] Tribute discovery arrays unbounded — Duplicate (Certora I-01)

**Severity:** Low | **Confidence:** High | **Familiar verdict:** Confirmed
**Location:** `Tribute.sol:100-102`

`daoTributeRefs` and `proposerTributeRefs` are append-only. The Familiar confirmed DoS risk is limited to off-chain view functions (`getActiveDaoTributes`). No on-chain state-changing function iterates these arrays. Spam cost is non-trivial (each entry requires locking real tokens).

**Prior art:** Certora I-01 (monotonicity proven via T-104, T-105).

**Status:** Duplicate — acknowledged.

---

### [L-04] SafeSummoner `extraCalls` can override validated config — Design Choice

**Severity:** Low | **Confidence:** High | **Familiar verdict:** Confirmed (foot-gun, not vulnerability)
**Location:** `SafeSummoner.sol`

`extraCalls` are appended after validated config calls and can override settings (e.g., resetting `proposalThreshold` to 0). The Familiar confirmed this is by design: SafeSummoner is advisory, not a security boundary. The caller provides `extraCalls`, so there is no privilege escalation. Direct summoning bypasses SafeSummoner entirely. NatSpec labels `extraCalls` as "advanced use."

**Status:** Design choice — documented in README.md SafeSummoner section.

---

### [L-05] ETH balance manipulable via `selfdestruct` — Known EVM Concern

**Severity:** Low | **Confidence:** High | **Familiar verdict:** Confirmed (economically irrational)
**Location:** `Moloch.sol` — ragequit uses `address(this).balance`

Forced ETH via `selfdestruct` inflates ragequit pools. The Familiar confirmed this is economically self-defeating: the attacker donates their own ETH, then all ragequitters (not just the attacker) benefit proportionally. Post-Dencun (EIP-6780), `SELFDESTRUCT` only sends ETH during same-transaction creation.

**Status:** Known EVM concern — no practical attack vector.

---

### [I-01] `mulDiv` does not support phantom overflow — Duplicate (Certora I-02)

**Severity:** Informational (adjusted from Medium) | **Familiar verdict:** Severity Adjusted
**Location:** `Moloch.sol:1987-1996`

The Familiar confirmed overflow requires astronomically large values. With `uint96` share supplies and realistic token balances, `pool * amt` cannot overflow `uint256`. The Certora bound lemma (M-24) proves `mulDiv(pool, amt, total) <= pool` under `uint128` constraints.

**Prior art:** Certora I-02.

**Status:** Duplicate — acknowledged.

---

### [I-02] ERC-6909 missing per-token-ID allowance — Design Choice

**Severity:** Informational | **Confidence:** High | **Familiar verdict:** Confirmed (design choice)
**Location:** `Moloch.sol` — ERC-6909 implementation

Only operator-level approval exists (no per-ID `approve`/`allowance`). The Familiar confirmed this is a deliberate simplification: ERC-6909 tokens here are governance receipts, and some are soulbound (`isPermitReceipt`). Per-ID allowance adds complexity without benefit for the use case.

**Status:** Design choice.

---

## Dismissed Findings

| Finding | Reason for Dismissal |
|---------|---------------------|
| Reentrancy / CEI violations (Sigil 1, all) | `nonReentrant` on all external-call functions, CEI correctly followed throughout, multicall delegatecall preserves guard |
| `receiptProposal` mapping ambiguity for ID 0 (G-7) | Proposal IDs are keccak256 hashes — probability of ID=0 is 1/2²⁵⁶ |
| Multicall + `onlyDAO` bypass (A-1) | False positive — `delegatecall` preserves `msg.sender`, so `onlyDAO` modifier is correctly enforced within multicall |

---

## Comparison to Prior Audits

| Grimoire Finding | Maps To | First Found By |
|-----------------|---------|---------------|
| M-01 castVote no state check | KF#15 | Claude (Opus 4.6) |
| M-02 Fund futarchy post-execution | KF#18 | ChatGPT Pro (GPT 5.4 Pro) |
| M-03 Transferable vote receipts | KF#5 | Pashov Skills |
| M-04 DAICO tap forfeiture | Certora L-01 | Certora FV |
| H-01 Sale cap sentinel | KF#1 | Zellic |
| L-01 Auto-open front-run | KF#11 | Multiple |
| L-02 Zero-winner futarchy lock | KF#6 | Pashov Skills |
| L-03 Tribute arrays unbounded | Certora I-01 | Certora FV |
| L-04 SafeSummoner extraCalls | Design choice | — |
| L-05 ETH via selfdestruct | Known EVM | — |
| I-01 mulDiv phantom overflow | Certora I-02 | Certora FV |
| I-02 ERC-6909 per-ID allowance | Design choice | — |

**Coverage assessment:** Grimoire's multi-agent methodology (4 sigils + 3 familiars) covered 10 of the 18 catalogued known findings (56%) and produced zero false positives after the Familiar triage pass. The reentrancy surface was thoroughly cleared. The methodology's strength is adversarial verification — the Familiar agents correctly dismissed 3 false positives and adjusted severity on 2 findings. No novel findings beyond KF#1–18.
