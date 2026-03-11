# Trail of Bits Skills — Sharp Edges + Code Maturity Assessment

**Skill:** [trailofbits/skills](https://github.com/trailofbits/skills) (Sharp Edges + Code Maturity)
Scan of: `Moloch.sol` (2110 lines)

Skills used:
- **Sharp Edges Analysis** — Identifies error-prone APIs, dangerous configurations, and footgun designs
- **Code Maturity Assessor** — 9-category maturity framework (arithmetic, auditing, access controls, complexity, decentralization, documentation, transaction ordering, low-level code, testing)

## Review Summary

> **Reviewed 2026-03-11. No production blockers identified.**
>
> - The Sharp Edges analysis identified **20 design footguns** (5 Critical, 7 High, 5 Medium, 3 Low). Most are configuration-dependent concerns already documented in our Configuration Guidance for Deployers (README.md). The analysis validates our existing guidance and reinforces the importance of setting `proposalThreshold > 0`, `timelockDelay > 0`, and careful futarchy configuration.
> - The Code Maturity Assessment scored **2.67/4.0 (Moderate-Satisfactory)** across 9 categories. Six categories rated Satisfactory (3), three rated Moderate (2). No category rated Weak (1) or Missing (0).
> - These analyses complement the vulnerability-focused audits (Zellic, Plainshift, Octane, Pashov) by evaluating design ergonomics and code quality rather than exploit paths.

---

## Part 1: Sharp Edges Analysis

### 1. Dangerous Defaults

#### 1.1 Zero Quorum Passes Proposals With 1 Vote - Critical

> **Review: Valid footgun, already documented.** When both `quorumBps=0` and `quorumAbsolute=0` (defaults), a single FOR vote passes any proposal. This is documented in our Configuration Guidance: DAOs should set appropriate quorum. The `summon()` function accepts `quorumBps` as a parameter, so deployers who set it to 0 are making a deliberate (if dangerous) choice. UIs should warn or prevent zero-quorum deployments.

When both quorum settings are zero, the `state()` function skips quorum checks entirely. A proposal passes the moment `forVotes > againstVotes`.

#### 1.2 Zero Proposal Threshold Lets Anyone Propose - High

> **Review: Valid footgun, already documented.** `proposalThreshold=0` is the default and means any shareholder can open proposals. This is intentional for small/trusted DAOs but dangerous at scale. Already covered in our Configuration Guidance: "Set `proposalThreshold > 0`."

When `proposalThreshold=0`, the threshold check is skipped. Any shareholder can open any proposal.

#### 1.3 Zero Timelock Means Instant Execution - High

> **Review: Valid footgun, already documented.** `timelockDelay=0` means proposals execute immediately on success, giving no window for members to ragequit before harmful proposals take effect. UIs should strongly recommend a non-zero timelock.

When `timelockDelay=0`, the queue and timelock are skipped entirely. Proposals execute in the same transaction they succeed.

#### 1.4 Zero ProposalTTL Means Proposals Never Expire - Medium

> **Review: Valid design choice.** Open-ended voting (`proposalTTL=0`) is intentional for DAOs that prefer no time pressure on governance. The risk of "zombie proposals" is real but mitigable via `bumpConfig()` to invalidate old proposals. Document as operational guidance.

When `proposalTTL=0`, proposals remain active indefinitely. Old proposals can be executed years later.

#### 1.5 Zero minYesVotesAbsolute Has No YES Floor - Medium

> **Review: Valid, compounds with 1.1.** Without a minimum YES threshold, proposals can pass with arbitrarily low turnout (as low as 1 vote). This is by design for flexible quorum configuration but should be documented as a footgun.

### 2. Configuration Cliffs

#### 2.1 Init Does Not Validate quorumBps Range - Critical

> **Review: Valid finding.** `setQuorumBps()` correctly rejects `bps > 10_000`, but `init()` does not validate. A `quorumBps` value exceeding 10000 at deploy time would make proposals permanently unpassable (quorum target exceeds total supply). **v2 hardening:** add `require(_quorumBps <= 10_000)` to `init()`.

The `init()` function accepts any `quorumBps` value without validation. Values exceeding 10000 basis points would brick the DAO permanently.

#### 2.2 bumpConfig Invalidates All In-Flight Proposals - High

> **Review: Valid, by design.** `bumpConfig()` is intentionally a nuclear option — it invalidates all pending proposals and permits. This is documented behavior for emergency governance situations. UIs should display prominent warnings before execution and show the count of affected proposals.

`bumpConfig()` increments `config`, which is included in all proposal/permit ID hashes. All existing proposals become unexecutable.

#### 2.3 Removing Ragequit While Timelock Is Zero Traps Members - High

> **Review: Valid dangerous combination.** If `ragequittable` is set to false while `timelockDelay=0`, members have no exit path before harmful proposals execute. UIs should prevent this combination or display strong warnings.

Setting `ragequittable=false` with no timelock removes both the exit mechanism and the exit window.

### 3. Silent Failures

#### 3.1 queue() Is a Silent No-Op When Timelock Is Zero - Medium

> **Review: Valid UX concern.** `queue()` returns silently when `timelockDelay=0`. Integrations that call `queue()` then wait for a timelock will wait indefinitely. Consider reverting with a descriptive error instead. **v2 hardening:** revert with `NoTimelock()` instead of silent return.

`queue()` returns silently without recording anything when `timelockDelay=0`.

#### 3.2 openProposal Is Silently Idempotent - Low

> **Review: By design.** Idempotency is intentional — `castVote` auto-opens proposals, and `fundFutarchy` also calls `openProposal`. Silent return on re-open prevents unnecessary reverts in these flows.

`openProposal` silently returns if the proposal is already opened.

#### 3.3 executeByVotes Return Signature Implies Soft Failure - Low

> **Review: Minor API ergonomics concern.** The `(bool ok, bytes memory retData)` return suggests soft failure, but `_execute` always reverts on failure. The return value is always `true`. Informational only.

### 4. Sentinel Value Confusion

#### 4.1 Sale cap=0 Means Unlimited, Not Zero - Critical

> **Review: Known quirk. Duplicate of Zellic #13.** Already documented in our Configuration Guidance. The cap is a soft guardrail. In minting mode, unlimited is the intended behavior. UIs should surface this clearly.

`cap=0` skips the cap check entirely, treating the sale as unlimited.

#### 4.2 rewardToken=address(0) Has Three Different Meanings - High

> **Review: Valid design footgun.** `address(0)` means "ETH" in `_payout()`, "use funder's choice" in `fundFutarchy()`, and "default to minted loot" in auto-futarchy via `openProposal()`. This triple-meaning creates confusion for deployers who set `autoFutarchyParam` without explicitly setting `rewardToken`. **v2 hardening:** use a distinct sentinel (e.g., `address(1)`) for "unset/use default" vs `address(0)` for ETH.

The same sentinel value `address(0)` has three different semantic meanings depending on context.

#### 4.3 address(1007) As Magic Number Sentinel - Low

> **Review: Informational.** Address 1007 (0x3EF) is in the precompile range where no legitimate ERC20 would be deployed on standard EVM chains. Theoretical chain-specific concern with no practical risk.

### 5. Dangerous Combinations

#### 5.1 ragequittable + minting sale + zero quorum = Treasury Drain - Critical

> **Review: Valid dangerous combination, already covered.** This is the union of multiple footguns documented in our Configuration Guidance. An attacker can buy shares via minting sale, pass a proposal instantly (zero quorum), and ragequit with the diluted treasury. Mitigated by setting quorum, threshold, or timelock to non-zero values.

The combination of unlimited minting, no quorum, and ragequit enables a single-transaction treasury drain.

#### 5.2 autoFutarchyParam + proposalThreshold=0 = Unbounded Loot Minting - Critical

> **Review: Valid dangerous combination. Duplicate of Octane vuln #4 / Pashov #3.** Already documented in our Configuration Guidance: "Be thoughtful with minted futarchy rewards" and "Set `proposalThreshold > 0`."

Permissionless proposal opening combined with auto-futarchy minted rewards allows unbounded loot creation.

#### 5.3 op=1 Delegatecall Is Nuclear - High

> **Review: By design. Duplicate of Octane warnings #2/#4.** Delegatecall governance is the standard mechanism for DAO upgrades across all governance frameworks. The trust assumption is that voters must trust the target code. UIs must clearly distinguish op=0 (call) from op=1 (delegatecall).

A proposal with `op=1` executes arbitrary code in the DAO's storage context.

#### 5.4 multicall Enables Batched Governance Actions - Medium

> **Review: By design.** A single proposal executing `multicall` can batch multiple `onlyDAO` actions atomically. This is intentional and useful (e.g., configuring multiple settings in one proposal). The risk is that a single proposal can remove all protections at once, but this requires passing a governance vote.

#### 5.5 Transferable Futarchy Receipts Enable Secondary Markets - Medium

> **Review: By design.** Vote receipt transferability is intentional for futarchy — receipts represent prediction market positions. The `cancelVote` breakage is a side effect (see Pashov #6). The secondary market for receipts is a feature of the prediction market mechanism.

#### 5.6 ragequittable + Futarchy Minted Loot = Double Extraction - High

> **Review: Valid concern. Duplicate of Plainshift #2 / Octane vuln #6.** Futarchy winners can cash out minted loot then ragequit for treasury assets. This is the same ragequit+futarchy interaction documented in our Configuration Guidance. Futarchy pools are incentives subordinate to governance — ragequit of all assets is by design.

### 6. Additional

#### 6.1 No Explicit Init Guard - Low

> **Review: Not a bug.** CREATE2 salt collision naturally prevents re-initialization. The second `init()` call fails at the `_init()` clone creation step.

#### 6.2 Receipt ID Collision With Proposal ID - Low

> **Review: Not a bug. Duplicate of Zellic #8.** Receipt IDs use a different hash prefix (`"Moloch:receipt"`). Collision requires breaking keccak256.

---

## Sharp Edges Summary

| # | Sharp Edge | Severity | Review |
|---|-----------|----------|--------|
| 1.1 | Zero quorum passes with 1 vote | Critical | Valid, documented in Config Guidance |
| 2.1 | Init doesn't validate quorumBps range | Critical | Valid, v2 hardening candidate |
| 4.1 | Sale cap=0 means unlimited | Critical | Known quirk (Zellic #13) |
| 5.1 | ragequittable + minting + zero quorum | Critical | Valid combo, documented |
| 5.2 | autoFutarchy + threshold=0 | Critical | Duplicate of Octane #4 |
| 1.2 | proposalThreshold=0 default | High | Valid, documented |
| 1.3 | timelockDelay=0 default | High | Valid, documented |
| 2.2 | bumpConfig nukes all proposals | High | By design (emergency) |
| 2.3 | No ragequit + no timelock | High | Valid combo |
| 4.2 | rewardToken=0 triple meaning | High | Valid, v2 hardening |
| 5.3 | op=1 delegatecall is nuclear | High | By design (all governance frameworks) |
| 5.6 | ragequit + futarchy minted loot | High | Duplicate of Plainshift #2 |
| 1.4 | proposalTTL=0 never expires | Medium | By design |
| 1.5 | minYesVotesAbsolute=0 no floor | Medium | Compounds with 1.1 |
| 3.1 | queue() silent no-op | Medium | v2 UX improvement |
| 5.4 | multicall batch governance | Medium | By design |
| 5.5 | Transferable futarchy receipts | Medium | By design |
| 3.2 | openProposal silent idempotent | Low | By design |
| 3.3 | Return signature misleading | Low | Informational |
| 4.3 | address(1007) magic number | Low | Informational |

---

## Part 2: Code Maturity Assessment

### Maturity Scorecard

| # | Category | Score | Rating | Review Note |
|---|----------|-------|--------|-------------|
| 1 | Arithmetic | 3 | Satisfactory | mulDiv, safe casts, checked arithmetic. Solid. |
| 2 | Auditing | 3 | Satisfactory | Comprehensive events. Missing events on settings changes is a valid gap. |
| 3 | Auth / Access Controls | 3 | Satisfactory | onlyDAO, SUMMONER, snapshot-based voting. No concerns. |
| 4 | Complexity Management | 2 | Moderate | Fair assessment. Monolithic file, Shares/Loot duplication. Trade-off for deployment simplicity. |
| 5 | Decentralization | 3 | Satisfactory | Ragequit, no admin keys, no upgradeability. Strong for Moloch model. |
| 6 | Documentation | 2 | Moderate | Fair. NatSpec coverage could improve. |
| 7 | Transaction Ordering | 3 | Satisfactory | Snapshot at N-1, maxPay slippage, sorted ragequit. Gold standard. |
| 8 | Low-Level Manipulation | 3 | Satisfactory | EIP-1153 reentrancy, Solady-style safe transfers, justified assembly. |
| 9 | Testing | 2 | Moderate | 418 tests, 7 files. Missing invariant tests is a valid gap for v2. |
| | **Average** | **2.67** | **Moderate-Satisfactory** | |

### Review of Assessment

> **Review: Fair and balanced assessment.** The 2.67/4.0 score accurately reflects a production-ready contract with room for improvement in complexity management, documentation, and testing methodology. The three Moderate ratings (complexity, documentation, testing) are valid:
>
> - **Complexity (2):** The monolithic file is a deliberate trade-off for deployment simplicity and gas optimization (single-file compilation). Shares/Loot duplication is real but minimal.
> - **Documentation (2):** NatSpec gaps are acknowledged. The README provides extensive documentation, but inline `@param`/`@return` coverage should improve.
> - **Testing (2):** 418 tests with fuzz coverage is substantial, but the lack of invariant/stateful fuzzing is a valid gap. This is the top priority for v2 hardening.
>
> The six Satisfactory ratings (arithmetic, auditing, auth, decentralization, transaction ordering, low-level) reflect genuine strengths of the codebase.

### Priority Improvements Acknowledged

| Priority | Recommendation | Status |
|----------|---------------|--------|
| P0 | Add invariant tests (vote totals, futarchy pools, ragequit math, delegation sums) | v2 candidate |
| P0 | Add events to settings functions | v2 candidate |
| P1 | Extract shared ERC20 logic from Shares/Loot | v2 candidate |
| P1 | Add full NatSpec to all public functions | v2 candidate |
| P1 | Configure foundry.toml fuzz settings | Actionable now |
| P2 | Add fuzz tests on core Moloch | v2 candidate |
| P3 | Commit-reveal voting | Future consideration |

---

> These analyses were performed using Trail of Bits Skills (sharp-edges + code-maturity-assessor) with manual review and cross-referencing against four prior audit reports (Zellic V12, Plainshift AI, Octane, Pashov Skills).
