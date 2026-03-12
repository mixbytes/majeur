# Certora Formal Verification — Audit Response

Evaluated: Certora FV report covering 7 contracts (Moloch, Shares, Loot, Badges, DAICO, Tribute, SafeSummoner).
142 properties verified. Prover version 8.8.1. Author: Specialist AI by [@DevDacian](https://x.com/DevDacian) ([@cyfrin](https://x.com/cyfrin)).

## Summary

> **All 142 properties pass except D-L1a, which is an intentional violation confirming finding L-01.**
>
> - 3 findings: 1 Low, 2 Informational.
> - All three are acknowledged. None require code changes.
> - The FV engagement is high quality — comprehensive invariant catalog, sound modeling, and correct use of ghost variables, inductive parametric rules, and harness-based abstraction.

---

## Finding Responses

### [L-01] DAICO `claimTap` advances `lastClaim` on partial claims — Acknowledged (By Design)

**Location:** `DAICO.sol:811`
**Certora rules:** D-L1a (violated — confirms finding), D-L1b (satisfied — demonstrates reachability)

The finding is valid: when `claimed < owed` (because `min(owed, allowance, daoBalance)` caps the payout), `lastClaim` advances to `block.timestamp`, forfeiting the difference.

**Why this is intentional:**

The only scenario where `claimed < owed` occurs in practice is when ragequit has drained treasury below the tap's accrued entitlement. Ragequit is a protest mechanism — members exit precisely because they disagree with how the DAO is spending (including ops compensation). If ragequitters drain the treasury, that *is* the signal: the DAO's members have chosen to withdraw capital rather than fund ops at the current rate.

Accumulating debt against a depleted treasury would create a perverse incentive: ops could accrue unbounded claims against a DAO that has been effectively abandoned by its members, then collect the full backlog if the treasury is ever replenished (e.g., by new members joining a sale). The current behavior — forfeiture on partial claims — correctly treats ragequit as a binding capital allocation decision by the membership.

The tap rate is set by governance. If the DAO is healthy and members support the ops relationship, the allowance will be sized appropriately and partial claims won't occur. If ragequit drains the treasury, the tap entitlement *should* be reduced — that's the Moloch exit mechanism working as designed.

**Mitigations already in production:**

1. `claimableTap(dao)` view (line 838) returns the actual claimable amount accounting for allowance and balance caps — ops tooling can monitor this and claim frequently to minimize exposure.
2. `setTapRate` (line 284) resets `lastClaim` to `block.timestamp` when the rate changes, preventing stale accrual after governance adjusts the rate.
3. The DAO controls the allowance (`Moloch.setAllowance`) — if governance wants to guarantee full tap coverage, it sizes the allowance above the maximum accrual window.

**Will not fix.** The forfeiture behavior aligns with the Moloch exit-rights model. Ops teams should call `claimTap` frequently (the function is permissionless — anyone can trigger it) to minimize the window of exposure to ragequit-induced partial claims.

---

### [I-01] Tribute discovery arrays grow unboundedly — Acknowledged

**Location:** `Tribute.sol:100-102`
**Certora rules:** T-104, T-105 (monotonicity proven)

The `daoTributeRefs` and `proposerTributeRefs` arrays are append-only. The monotonicity proofs confirm they never shrink, supporting the unbounded growth concern.

**Why this is acceptable:**

These arrays serve only `getActiveDaoTributes` and `getProposerTributeCount` — view functions used for off-chain discovery. No state-changing function iterates them. The core tribute lifecycle (`proposeTribute`, `cancelTribute`, `claimTribute`) uses the `tributes` mapping directly and is O(1) regardless of array size.

In practice, tribute proposals are infrequent governance events, not high-frequency operations. A DAO would need thousands of propose/cancel cycles to cause RPC gas limit issues on the view function. Frontends can use event indexing (`TributeProposed`, `TributeCancelled`, `TributeClaimed`) as a more scalable discovery mechanism.

**Will not fix.** If needed, paginated view functions can be added in a future peripheral contract without modifying Tribute.sol.

---

### [I-02] `mulDiv` does not support phantom overflow — Acknowledged

**Location:** `Moloch.sol:1987-1996`
**Certora rule:** M-24 (bound lemma proven under `uint128` constraints)

The `mulDiv` function reverts when `x * y` overflows `uint256` even if `x * y / d` would fit. The Certora bound lemma proves `mulDiv(pool, amt, total) <= pool` when `amt <= total` under `uint128` bounds.

**Why this is not a concern:**

Every callsite is bounded by protocol parameters:
- **Ragequit:** `amt` is burn amount (capped by `uint96` share/loot supply). `pool` is a token balance — would need >3.4×10³⁸ units to overflow with `uint96` amt.
- **Auto-futarchy earmark:** `p <= 10_000` and `basis` is `uint96` supply.
- **Split delegation:** `B[i] <= 10_000` and `bal` is token balance.
- **Futarchy payout:** Fixed `1e18` multiplier with realistic pool sizes.

Replacing with Solady's 512-bit `mulDiv` would add gas cost for zero practical benefit.

**Will not fix.**

---

## FV Coverage Assessment

The verification covers the critical protocol invariants well. Notable strengths:

| Area | Properties | Technique |
|------|-----------|-----------|
| ERC-6909 / ERC-20 accounting | Sum-of-balances invariants | Ghost variables + Sstore/Sload hooks |
| Proposal state machine | Write-once fields, executed latch, terminal state | Parametric rules over all functions |
| Split delegation | BPS sum, max splits, no zero/duplicate delegates | Inductive parametric rules |
| Bidirectional mapping (Badges) | seatOf ↔ _ownerOf consistency | 5 coupled invariants with requireInvariant |
| Access control | onlyDAO enforcement across 14 setters | Filtered parametric rule |
| Sale/allowance integrity | Cap decrease, slippage revert, spend decrease | Integrity + revert condition rules |

**Out of scope (by design):** Cross-contract properties (voting power conservation, ragequit end-to-end), transient storage reentrancy guard, ragequit token loop mechanics, `keccak256`-based intent hash reasoning. These are reasonable exclusions for single-contract harness verification.
