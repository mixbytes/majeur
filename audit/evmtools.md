# EVM MCP Tools — Moloch.sol

**Tool:** [0xGval/evm-mcp-tools](https://github.com/0xGval/evm-mcp-tools) (Ethereum Tools for Claude MCP)
**Type:** On-chain contract security scanner (Etherscan-verified source, regex heuristics)
**Target:** `src/Moloch.sol` (2110 lines, 5 contracts)

## Tool Overview

EVM MCP Tools is an MCP server providing Ethereum blockchain analysis tools for Claude. The `auditContract` tool fetches Etherscan-verified source code and runs `analyzeContractSecurity()` — a function that performs 5 string-match heuristic checks:

| # | Pattern | Severity | What It Detects |
|---|---------|----------|-----------------|
| 1 | `call.value` without `ReentrancyGuard` | High | Reentrancy via ETH sends |
| 2 | `tx.origin` | Medium | Authentication via `tx.origin` |
| 3 | `.call(` or `.delegatecall(` without `require` | Medium | Unchecked low-level calls |
| 4 | `block.timestamp` or `now` | Low | Timestamp dependence |
| 5 | `selfdestruct` or `suicide` | High | Self-destruct capability |

**Limitation:** The tool only works on deployed/verified contracts via Etherscan API — it cannot analyze local source files. For this report, we apply the 5 heuristics manually against the Moloch.sol source code.

## Heuristic Results

### Check 1: `call.value` without `ReentrancyGuard` — NOT TRIGGERED

Moloch.sol uses Solady-style assembly `safeTransferETH` (line ~1914) and `safeTransfer`/`safeTransferFrom` for ERC-20s. There is no `call.value` pattern. The contract uses EIP-1153 transient storage for reentrancy protection (`nonReentrant` modifier at line ~1850), which is stronger than OpenZeppelin's `ReentrancyGuard` but would not be detected by this regex since it searches for the literal string "ReentrancyGuard".

> **Review:** The heuristic would produce a **false positive** if it matched `.call{value:` (the modern Solidity syntax) without recognizing transient-storage reentrancy guards. The regex only looks for the legacy `call.value` pattern and the string "ReentrancyGuard", missing both modern call syntax and non-OZ guard implementations.

### Check 2: `tx.origin` — NOT TRIGGERED

Moloch.sol does not use `tx.origin` anywhere. All authorization is via `msg.sender` checks (`onlyDAO` modifier, badge holder checks, share/loot holder checks).

> **Review:** Correct result. No false positive or false negative.

### Check 3: `.call(` / `.delegatecall(` without `require` — TRIGGERED (partial)

Moloch.sol uses low-level `.call` in the `_execute` function (line ~490):
```solidity
(bool ok,) = to.call{value: value}(data);
```
And `.delegatecall`:
```solidity
(bool ok,) = to.delegatecall(data);
```
Both are followed by `require(ok)` (line ~494). The heuristic checks for `.call(` without a nearby `require`, but the implementation uses `if (!ok) revert NotOk()` or `require(ok, ...)` — whether this triggers depends on the regex's proximity window.

The `safeTransferETH` assembly block uses raw `call` in assembly (not `.call(` Solidity syntax), which would not be matched.

> **Review:** If triggered, this would be a **false positive** — the return value is checked. The heuristic cannot parse control flow, so it may flag the `.call{value:` even though the very next line checks the result.

### Check 4: `block.timestamp` — TRIGGERED

Moloch.sol uses `block.timestamp` extensively for governance timing:
- `createdAt[id] = uint64(block.timestamp)` (proposal opening)
- `queuedAt[id] = uint64(block.timestamp)` (timelock queuing)
- Expiry checks: `block.timestamp > createdAt[id] + proposalTTL`
- Timelock checks: `block.timestamp >= queuedAt[id] + timelockDelay`

> **Review:** **True positive but informational only.** Timestamp usage here is standard governance timing — proposals need time-based expiry and timelocks. Miner manipulation of `block.timestamp` (±15 seconds) is irrelevant to governance windows measured in hours/days. Every governor contract (OZ Governor, Compound, Nouns) uses `block.timestamp` identically. This is a known limitation of the heuristic — it cannot distinguish dangerous timestamp reliance (e.g., randomness, auction deadlines) from safe usage (governance timing).

### Check 5: `selfdestruct` / `suicide` — NOT TRIGGERED

Moloch.sol does not contain `selfdestruct` or `suicide`. The contract is not self-destructible.

> **Review:** Correct result. No false positive or false negative.

## Summary

| Check | Result | Assessment |
|-------|--------|------------|
| `call.value` reentrancy | Not triggered | Would be FP if triggered — transient storage guard not recognized |
| `tx.origin` | Not triggered | Correct |
| Unchecked `.call`/`.delegatecall` | Partial trigger | FP — return values are checked |
| `block.timestamp` | Triggered | True positive but informational — standard governance timing |
| `selfdestruct` | Not triggered | Correct |

**Confirmed findings: 0** (1 informational that is standard practice)
**False positives: 1** (unchecked call, if triggered)
**Novel findings: 0**

## Tool Assessment

EVM MCP Tools' `auditContract` is a **basic entry-level scanner** with significant limitations:

1. **Regex-only analysis** — No AST parsing, no control flow analysis, no data flow tracking. Cannot understand that a `require(ok)` on the next line covers a `.call`.
2. **Only 5 checks** — Misses entire vulnerability classes: access control, logic errors, reentrancy via callbacks (not just `call.value`), flash loan attacks, governance-specific issues, precision errors, etc.
3. **Etherscan-only** — Cannot audit unverified or local contracts. Requires deployment first.
4. **No governance awareness** — Zero checks for snapshot manipulation, quorum gaming, delegation attacks, proposal lifecycle issues, or any of the patterns that matter for a DAO contract.
5. **Legacy patterns** — Searches for `call.value` (pre-0.7 syntax) and `suicide` (deprecated since 0.5). Modern Solidity uses `.call{value:}` and `selfdestruct`.
6. **No reentrancy guard diversity** — Only recognizes the literal string "ReentrancyGuard", missing transient storage guards, mutex patterns, or custom implementations.

For Moloch.sol specifically, this tool would produce at most 1 informational finding (`block.timestamp`) that every governance contract shares. It adds no signal beyond what any developer already knows.

## Cross-Reference

All 0 findings are consistent with the 14 deduplicated findings from 13 prior audits. No novel contributions.

| Prior Audit | Overlap |
|-------------|---------|
| All 13 prior audits | No overlap — tool did not surface any of the known findings |

The tool's 5 heuristics are entirely orthogonal to the actual attack surface identified by deeper scanners (Pashov, Forefy, HackenProof triage). It would not detect any of the real findings: futarchy resolution timing, vote receipt transferability, quorum manipulation, sale cap sentinel collision, etc.
