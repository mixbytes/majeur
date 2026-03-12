# Moloch (Majeur) DAO Framework

**Opinionated DAO governance** — members can always exit with their share of the treasury. Built-in futarchy, weighted delegation, and soulbound badges.

**Majeur is for DAOs that prioritize member protection.** Ragequit means no one can be trapped — if you disagree with the majority, burn your shares and leave with your proportional treasury. Futarchy rewards voters who bet correctly on outcomes, not just those who show up. Split delegation lets you diversify representation instead of all-or-nothing.

## At a Glance

```
Vote with shares → Split delegation → Futarchy markets → Ragequit exit
     ↓                    ↓                  ↓                ↓
Execute any         60% Alice          Reward correct    Leave with your
on-chain action     40% Bob            predictions       treasury share
```

## Token System

| Token | Standard | Purpose |
|-------|----------|---------|
| **Shares** | ERC-20 | Voting power + economic rights (delegatable) |
| **Loot** | ERC-20 | Economic rights only — no voting |
| **Receipts** | ERC-6909 | Vote receipts for futarchy payouts |
| **Badges** | ERC-721 | Soulbound NFTs for top 256 shareholders |

All tokens are deployed as separate contracts via minimal proxy clones. The DAO controls minting, burning, and transfer locks.

## Core Concepts

### Ragequit
The defining feature of Moloch-style DAOs: **members can always exit**.

Burn your shares/loot → receive your proportional share of the treasury. Own 10% of shares? Claim 10% of every treasury token. This creates a floor price for membership and protects minorities from majority tyranny.

*Limitation: You can only claim external tokens (ETH, USDC, etc.) — not the DAO's own shares, loot, or badges.*

### Futarchy
Skin-in-the-game governance through prediction markets:

1. Anyone funds a reward pool for a proposal
2. Vote YES, NO, or ABSTAIN → receive receipt tokens
3. Proposal passes → YES voters split the pool; fails → NO voters win
4. Burn your receipts to claim winnings

This shifts incentives from "vote with the crowd" to "vote for what you believe will actually succeed."

### Split Delegation
Distribute voting power across multiple delegates:

```
Traditional:  100% → Alice
Split:        60% → Alice, 40% → Bob, or any combination
```

Useful when you trust different people for different expertise, or want to hedge your representation.

### Badges
Soulbound NFTs automatically minted for the top 256 shareholders. They update in real-time as balances change and gate access to member-only features like on-chain chat.

## Proposal Lifecycle

```
Unopened → Active → Succeeded → Queued (if timelock) → Executed
                 ↘ Defeated
                 ↘ Expired (TTL)
```

**Pass conditions** (all must be true):
- Quorum reached (absolute or percentage)
- FOR > AGAINST (ties fail)
- Minimum YES threshold met (if configured)
- Not expired

## Quick Start

### Create & Vote on Proposals

```solidity
// 1. Create proposal ID (anyone can compute this)
uint256 proposalId = dao.proposalId(
    0,                    // op: 0=call, 1=delegatecall
    target,               // contract to call
    value,                // ETH to send
    data,                 // calldata
    nonce                 // unique nonce
);

// 2. Open and vote (auto-opens on first vote)
dao.castVote(proposalId, 1);  // support: 0=AGAINST, 1=FOR, 2=ABSTAIN

// 3. Execute when passed
dao.executeByVotes(0, target, value, data, nonce);
```

### Futarchy Markets

```solidity
// Fund a prediction market for a proposal
dao.fundFutarchy(
    proposalId,
    address(0),  // 0 = ETH, or token address
    1 ether      // amount
);

// After resolution, claim winnings
uint256 receiptId = dao._receiptId(proposalId, 1); // 1=YES
dao.cashOutFutarchy(proposalId, myReceiptBalance);
```

### Token Sales

```solidity
// DAO enables share sales (governance action)
dao.setSale(
    address(0),  // payment token (0=ETH, or ERC-20 address)
    0.01 ether,  // price per share (in payment token units)
    1000e18,     // cap (max shares that can be sold)
    true,        // mint new shares (false = transfer from DAO treasury)
    true,        // active (enable sales)
    false        // isLoot (false = shares, true = loot)
);

// Users can buy shares
dao.buyShares{value: 1 ether}(
    address(0),  // payment token (must match the sale config)
    100e18,      // shares to buy
    1 ether      // max payment willing to spend (slippage protection)
);
// Payment goes to DAO treasury, buyer receives shares/loot
```

### Ragequit

```solidity
// Exit with proportional share of treasury
address[] memory tokens = [weth, usdc, dai];
dao.ragequit(
    tokens,      // tokens to claim
    myShares,    // shares to burn
    myLoot       // loot to burn
);
```

## Advanced Features

### Pre-Authorized Permits

DAOs can issue permits allowing specific addresses to execute actions without voting:

```solidity
// DAO issues permit
dao.setPermit(op, target, value, data, nonce, alice, 1);

// Alice spends permit
dao.spendPermit(op, target, value, data, nonce);
```

### Timelock Configuration

```solidity
dao.setTimelockDelay(2 days);  // Delay between queue and execute
dao.setProposalTTL(7 days);     // Proposal expiry time
```

## Features

### Governance
| Feature | Description |
|---------|-------------|
| Snapshot voting | Block N-1 snapshot prevents vote buying after proposal opens |
| Flexible quorum | Absolute (e.g., 1000 votes) or percentage (e.g., 20%) |
| Timelocks | Configurable delay between passing and execution |
| Proposal TTL | Auto-expire stale proposals |
| Vote/proposal cancellation | Change your mind before execution |

### Economics
| Feature | Description |
|---------|-------------|
| Ragequit | Exit with proportional treasury share |
| Token sales | Built-in share/loot sales at configurable price |
| DAICO | External sale contract with tap mechanism (controlled fund release) |
| Tribute | OTC escrow for membership trades |
| Futarchy | Prediction markets reward correct voters |

### Technical
| Feature | Description |
|---------|-------------|
| Split delegation | Divide voting power across multiple delegates |
| ERC-6909 receipts | Gas-efficient multi-token for vote tracking |
| Clone pattern | ~80% deployment gas savings |
| Transient storage | EIP-1153 reentrancy guards |
| On-chain SVG | Fully decentralized metadata — no IPFS, no servers |

## Contract Architecture

```
Summoner (Factory)
└── Deploys via CREATE2 + minimal proxy clones
    │
    ├── Moloch (Main DAO Contract)
    │   ├── Governance logic (proposals, voting, execution)
    │   ├── ERC-6909 receipts (multi-token vote receipts)
    │   ├── Futarchy markets
    │   ├── Ragequit mechanism
    │   └── Token sales
    │
    ├── Shares (Separate ERC-20 + ERC-20Votes Clone)
    │   ├── Voting power tokens
    │   ├── Transferable/Lockable (DAO-controlled)
    │   ├── Single delegation or split delegation
    │   └── Checkpoint-based vote tracking
    │
    ├── Loot (Separate ERC-20 Clone)
    │   ├── Non-voting economic tokens
    │   └── Transferable/Lockable (DAO-controlled)
    │
    └── Badges (Separate ERC-721 Clone)
        ├── Soulbound (non-transferable) NFTs
        ├── Automatically minted for top 256 shareholders
        └── Auto-updated as balances change
```

## Peripheral Contracts

### Tribute (OTC Escrow)

Simple escrow for "tribute proposals" — trade external assets for DAO membership:

```solidity
// 1. Proposer locks tribute (e.g., 10 ETH for 1000 shares)
tribute.proposeTribute{value: 10 ether}(
    dao,           // target DAO
    address(0),    // tribTkn (ETH)
    0,             // tribAmt (use msg.value for ETH)
    sharesToken,   // forTkn (what proposer wants)
    1000e18        // forAmt (how much)
);

// 2. DAO votes to accept, then claims (executes the swap)
// DAO receives tribute, proposer receives shares
dao.executeByVotes(...); // calls tribute.claimTribute(proposer, tribTkn)
```

**Key functions:**
- `proposeTribute()` - Lock assets and create offer
- `cancelTribute()` - Proposer withdraws (before DAO claims)
- `claimTribute()` - DAO accepts and executes swap
- `getActiveDaoTributes()` - View all pending tributes for a DAO

### DAICO (Token Sale + Tap)

Inspired by Vitalik's DAICO concept — controlled fundraising with investor protection:

```solidity
// 1. DAO configures a sale
dao.executeByVotes(...); // calls DAICO.setSaleWithTap(...)

// 2. Users buy shares/loot
daico.buy(dao, address(0), 1 ether, minShares);  // exact-in
daico.buyExactOut(dao, address(0), 1000e18, maxPay);  // exact-out

// 3. Ops team claims vested funds via tap
daico.claimTap(dao);  // anyone can trigger, funds go to ops
```

**Sale Features:**
- Fixed-price OTC sales (tribAmt:forAmt ratio)
- Optional deadline expiry
- Optional LP integration with ZAMM (auto-adds liquidity)
- Drift protection prevents buyer underflow when spot > OTC price

**Tap Mechanism:**
- `ratePerSec` - Funds release rate (smallest units/second)
- `ops` - Beneficiary address (can be updated by DAO)
- Rate changes are non-retroactive (prevents gaming)
- Dynamically caps to min(owed, allowance, balance) — respects ragequits


## FAQ

### Q: Can I delegate to myself?
**A:** Yes, and it's the default. Your votes stay with you unless you explicitly delegate.

### Q: What's the difference between `call` and `delegatecall` in proposals?
**A:** 
- `call` (op=0): Execute from DAO's context (normal)
- `delegatecall` (op=1): Execute in DAO's storage (upgrades/modules)

### Q: Can I partially ragequit?
**A:** Yes! Specify how many shares/loot to burn. You don't have to exit completely.

### Q: How are proposal IDs generated?
**A:** Deterministically from: `keccak256(dao, op, to, value, data, nonce, config)`. Anyone can compute it.

### Q: Can the DAO upgrade itself?
**A:** Yes, through proposals with `delegatecall` or by deploying new contracts.

### Q: What's the `config` parameter?
**A:** A version number that's part of every proposal ID. The DAO can increment it via `bumpConfig()` to invalidate all old/pending proposal IDs and permits. This is a governance "emergency brake" if malicious proposals were created.

