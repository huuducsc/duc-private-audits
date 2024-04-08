# Takadao Security Review
###### tags: `private`, `takaDao`

A security review of the [Takadao](https://takadao.io/#) smart contract protocol was done by [TrungOre](https://twitter.com/Trungore) and [duc](https://twitter.com/duc_hph). \
This audit report includes all the vulnerabilities, issues and code improvements found during the security review.

# Disclaimer
A smart contract security review cannot assure the absolute absence of vulnerabilities. It involves a constrained allocation of time, resources, and expertise to identify as many vulnerabilities as possible. I cannot provide a guarantee of 100% security following the review, nor can I guarantee that any issues will be discovered during the review of your smart contracts.

# Severity Classification 
**High** - leads to a significant material loss of assets in the protocol or significantly harms a group of users.

**Medium** - only a small amount of funds can be lost (such as leakage of value) or a core functionality of the protocol is affected.

**Low** - can lead to any kind of unexpected behaviour with some of the protocol's functionalities that's not so critical.

# Protocol Overview 
Takaturn are mini DAOs that are created for a defined period of time to fund a cooperative loan. Participants of the DAO pay a predetermined amount into the DAO contract on a regular basis (weekly or monthly) and take turns to receive the entirety of the DAO fund (the “money pot”). Each participant puts up collateral to create a trustless system. At the end of the DAO term, everyone will have been the beneficiary once and all collateral will be returned. 

![](https://hackmd.io/_uploads/rJTaj9iS3.png)

For further background of Takadao protocol, refer to:
* whitepaper: https://takadao.gitbook.io/takaturn-whitepaper/
* docs: https://app.gitbook.com/o/ot8mO8k6Wyg8WohrniYU/home

# Security Assessment Summary

**_review commit hash_ - [6bb7a13ecb08aed08811239b963fac90b44e6ada](https://github.com/TakafulDAO/takaturn/commit/6bb7a13ecb08aed08811239b963fac90b44e6ada)**

## Scope

The following smart contracts were in scope of the audit:

- `Collateral.sol`
- `Fund.sol`
- `TakaturnFactory.sol`

The following number of issues were found, categorized by their severity:

- High: 2 issues
- Medium: 4 issues
- Low: 5 issues

# Findings Summary 
| ID           | Title                                                                                                                                                        | Severity | Status  |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |  -------- | ------- |
| [H-01](#H01) | Incorrect calculation of remainingCycles in the _isUnderCollaterized function | HIGH | Pending |
| [H-02](#H02) |  USDC blacklist is vulnerable for the process of `requestContribution()`                                                                                  | HIGH     | Pending |
| [M-01](#M01) |     Oracle data can be outdated                                                                           | MEDIUM     | Pending |
| [M-02](#M02) | Missing check for the status of Arbitrum  sequencer                                                                                        | MEDIUM     | Pending |
| [M-03](#M03) |    The collateral will be distributed unfairly if all participants are undercollateralized                                                                            | MEDIUM   | Pending |
| [M-04](#M04) |     Only the first participant is checked in the `initiateFundContract` function                                                                                                              | MEDIUM   | Pending |
| [L-01](#L01) |   Redundant conversion `address(msg.sender)` | LOW      | Pending |
| [L-02](#L02) | There is no need to initialize the value to 0 | LOW | Pending |
| [L-03](#L03) | Inconsistent use of `require` and `revert` | LOW | Pending |
| [L-04](#L04) | Should check if `contributionPeriod` is less than `cycleTime` in constructor of Fund contract | LOW | Pending |
| [L-05](#L05) | The `closeFundingPeriod` and `startNewCycle` functions should not restrict the caller to only the owner | LOW | Pending |

# Detailed Findings

## <a id="High"></a>High

### <a id="H01"></a> [H-01] Incorrect calculation of remainingCycles in the _isUnderCollaterized function 
#### Description
The `_isUnderCollateralized` function verifies whether a user's collateral is below 1.0x of their total contribution amount. This function calculates the `collateralLimit` and checks if the user's collateral in USD is below that limit, returning a boolean value indicating the result.
```solidity=
if (fundContract == address(0)) {
    collateralLimit = totalParticipants * contributionAmount * 10 ** 18;
} else {
    uint remainingCycles = 1 + counterMembers - _fundInstance.currentCycle();
    collateralLimit = remainingCycles * contributionAmount * 10 ** 18; // Convert to Wei
}
```
When a user participates in a funding cycle (`fundContract` != `address(0)`), the calculation of the `collateralLimit` involves the usage of the `remainingCycles`. However, there is an issue with the calculation of `remainingCycles`. The problem arises from the fact that the `counterMembers` value never changes during the funding cycle, even though the actual `remainingCycles` should decrease if `Fund.totalAmountOfCycles` decreases (due to someone being expelled). This leads to an incorrect assessment of collateralization for the user. As a result, users may be considered undercollateralized and expelled, even when their collateral is sufficient to contribute to the remaining cycles.

#### Impact
User might be undercollateralized and expelled even when their collateral are enough to contribute for the remaining cycles.

#### Code Snippet
https://github.com/TakafulDAO/takaturn/blob/6bb7a13ecb08aed08811239b963fac90b44e6ada/ethereum/contracts/Collateral.sol#L365

#### Tool used
Manual Review

#### Recommendation
The calculation of remainingCycles should be based on the Fund.totalAmountOfCycles variable instead of counterMembers

---

### <a id="H02"></a> [H-02] USDC blacklist is vulnerable for the process of `requestContribution()` 
#### Description
USDC has a special mechanism that reverts any transfer transaction containing a blacklisted address. You can refer to [this link](https://twitter.com/usdcblacklist?lang=en) to stay updated on the blacklist.

Let's consider the scenario where a user who has joined the fund becomes blacklisted in a later cycle. Assume that Bob has joined the fund as a beneficiary and has enabled autoPay, which automatically pays the USDC in each cycle. In cycle `x`, Bob gets blacklisted, causing the `Fund.closeFundingPeriod()` function to revert.

The reason for this scenario is that the `Fund.closeFundingPeriod()` function attempts to call `_autoPay()` during each call. This internal function, in turn, calls `_payContribution()` to transfer USDC from users who have sufficient balance and allowance to the Fund contract.

```solidity=
/// link: https://github.com/TakafulDAO/takaturn/blob/6bb7a13ecb08aed08811239b963fac90b44e6ada/ethereum/contracts/Fund.sol#L340-L351

function _payContribution(address payer, address participant) internal {
    // Get the amount and do the actual transfer
    // This will only succeed if the sender approved this contract address beforehand
    uint amount = contributionAmount;

    bool success = stableToken.transferFrom(payer, address(this), amount);
    require(success, "Contribution failed, did you approve stable token?");

    // Finish up, set that the participant paid for this cycle and emit an event that it's been done
    paidThisCycle[participant] = true;
    emit OnPaidContribution(participant, currentCycle);
}
```
If the function is applied to Bob, it will revert due to the presence of a blacklisted address. Consequently, the entire process of the `Fund.closeFundingPeriod()` function will also revert.

#### Impact
Users are unable to take out the loan due to the transaction being reverted. 

#### Code Snippet
https://github.com/TakafulDAO/takaturn/blob/6bb7a13ecb08aed08811239b963fac90b44e6ada/ethereum/contracts/Fund.sol#L324-L351

#### Tool used
Manual Review

#### Recommendation
Using try/catch when executing transfer the USDC tokens. 

---

## <a id="Medium"></a>Medium

### <a id="M01"></a> [M-01] Oracle data can be outdated
#### Description
The `lastRoundData()`'s parameters according to [Chainlink](https://docs.chain.link/docs/data-feeds/price-feeds/api-reference/) are the following:
```solidity=
function latestRoundData() external view
    returns (
        uint80 roundId,             //  The round ID.
        int256 answer,              //  The price.
        uint256 startedAt,          //  Timestamp of when the round started.
        uint256 updatedAt,          //  Timestamp of when the round was updated.
        uint80 answeredInRound      //  The round ID of the round in which the answer was computed.
    )
```
These return value are meant to be used to do some [checks](https://docs.chain.link/data-feeds/historical-data#getrounddata-return-values) before updating the price. By just getting the price, user will be affected by the stale price and incomplete rounds. 

#### Impact
Function `Collateral.getLatestPrice()` calls out to a Chainlink oracle receiving the `lastestRoundData()`. If there is a problem with Chainlink starting a new round or finding consensus on the new value for the oracle (e.g. chainlink nodes abandon the oracle, chain congestion, vulnerability/attacks on the chainlink system), the contract will continue using outdated / incorrect data. This can lead to some serious screnarios when calculating the collateral value of a user and make it expelled by mistake. 

#### Code Snippet
https://github.com/TakafulDAO/takaturn/blob/6bb7a13ecb08aed08811239b963fac90b44e6ada/ethereum/contracts/Collateral.sol#L320-L328

#### Tool used
Manual Review

#### Recommendation
Add the recommended checks:
```solidity=
(
    uint80 roundID,
    int256 price,
    ,
    uint256 timeStamp,
    uint80 answeredInRound
) = priceFeed.latestRoundData();
require(
    timeStamp != 0,
    “ChainlinkOracle::getLatestAnswer: round is not complete”
);
require(
    answeredInRound >= roundID,
    “ChainlinkOracle::getLatestAnswer: stale data”
);
require(price > 0, "Chainlink Malfunction”);
```

---

### <a id="M02"></a> [M-02] Missing check for the status of Arbitrum sequencer 
#### Description
The protocol wants to deploy for Arbitrum.

Chainlink recommends that all Arbitrum oracles consult the Sequencer Uptime Feed to ensure that the sequencer is live before trusting the data returned by the oracle. There is no such check implemented in the `Collateral.sol`

#### Impact
If the Arbitrum Sequencer goes down, oracle data will not be kept up to date, and thus could become stale. However, users are able to continue to interact with the protocol directly through the L1 contract. You can review [Chainlink docs](https://docs.chain.link/data-feeds/l2-sequencer-feeds) on L2 Sequencer Uptime Feeds for more details on this.

As a result, owner may be able to use the protocol while oracle feeds are stale. Then outdated price can be used to calculate the collateral value.

#### Code Snippet
https://github.com/TakafulDAO/takaturn/blob/6bb7a13ecb08aed08811239b963fac90b44e6ada/ethereum/contracts/Collateral.sol#L320-L328

#### Tool used
Manual Review

#### Recommendation
Add a check for sequencer status similar to example of chainlink recommend: 
https://docs.chain.link/data-feeds/l2-sequencer-feeds#example-code

---

### <a id="M03"></a> [M-03] The collateral will be distributed unfairly if all participants are undercollateralized 
#### Description
We will consider one edge-case in which all the participants are undercollateralized / don't have enough collateral to pay for the current cycle and should be expelled (It also means that nobody has paid for this cycle). 

When this scenario happens, if we call `Fund.closeFundingPeriod()` the first participant will be chosen as the beneficiary for the cycle since the `beneficiaryIndex` is [initialized with value 0](https://github.com/TakafulDAO/takaturn/blob/6bb7a13ecb08aed08811239b963fac90b44e6ada/ethereum/contracts/Fund.sol#LL376C14-L376C30).

The function will then [execute the external call](https://github.com/TakafulDAO/takaturn/blob/6bb7a13ecb08aed08811239b963fac90b44e6ada/ethereum/contracts/Fund.sol#L409-L410) to `Collateral.requestContribution()`, where the param `beneficiary` is `Fund.beneficiariesOrder[0]` and `defaulters` is the entire array `Fund.beneficiariesOrder[]`, to request contribution from collateral from defaulters. 

During the first for-loop of the function `Collateral.requestContribution()`, the memory variable `share` is calculated as the sum of all participants that are expelled in the current cycle. Combine this with our assumption of the edge-case, the `share` will be the sum of all collateral value of all participants except the first participant since the beneficiary is excluded in this [line](https://github.com/TakafulDAO/takaturn/blob/6bb7a13ecb08aed08811239b963fac90b44e6ada/ethereum/contracts/Collateral.sol#L180). 
```solidity=
/// link: https://github.com/TakafulDAO/takaturn/blob/6bb7a13ecb08aed08811239b963fac90b44e6ada/ethereum/contracts/Collateral.sol#L178-L190

/// auditor comment: beneficiary is excluded in this for-loop 
if (currentDefaulter == ben) continue; // Avoid expelling graced defaulter

if (
    (wasBeneficiary && _isUnderCollaterized(currentDefaulter)) ||
    (currentDefaulterBank < contributionAmountWei)
) {
    isCollateralMember[currentDefaulter] = false; // Expelled!
    expellants[i] = currentDefaulter;
    share += currentDefaulterBank;
    collateralMembersBank[currentDefaulter] = 0;
    totalExpellants++;
```
The sum collateral `share` will be then distributed among all the participants that aren't expelled and haven't been beneficiary yet. In this case only the first participant is satisified the conditions since the remaining are expelled. 
```solidity=
/// link: https://github.com/TakafulDAO/takaturn/blob/6bb7a13ecb08aed08811239b963fac90b44e6ada/ethereum/contracts/Collateral.sol#L218-L224

if (nonBeneficiaryCounter > 0) {
    // This case can only happen when what?
    share = share / nonBeneficiaryCounter;
    for (uint i = 0; i < nonBeneficiaryCounter; i++) {
        collateralPaymentBank[nonBeneficiaries[i]] += share;
    }
}
```
So the first participant will claim all collaterals of all other participants. 

#### Impact
Unfair distribution among the participants. All of the participants are in the same condition (undercollateralized and should be expelled) but only the first participants have the privilege to claim all the collaterals. 

#### Code Snippet
https://github.com/TakafulDAO/takaturn/blob/6bb7a13ecb08aed08811239b963fac90b44e6ada/ethereum/contracts/Collateral.sol#L180
https://github.com/TakafulDAO/takaturn/blob/6bb7a13ecb08aed08811239b963fac90b44e6ada/ethereum/contracts/Collateral.sol#L219-L223

#### Tool used
Manual Review

#### Recommendation
Consider to close fund immediately when collateral of participants aren't enough to pay for the cycle. It will let all participants claim their remaining collateral when the case happens. 
---

### <a id="M04"></a> [M-04] Only the first participant is checked in the initiateFundContract function
#### Description
The `initiateFundContract` function in the Collateral contract only checks the collateralization status of the first participant in the participants list. 
```solidity=
function initiateFundContract()
        external
        onlyOwner
        atState(States.AcceptingCollateral)
    {
        ...
        require(
            !_isUnderCollaterized(participants[0]), "Eth prices dropped");
        ...
```
If the first participant (participants[0]) is undercollateralized, the function will revert. However, if participants[0] is not undercollateralized and other participants become undercollateralized, the fund contract will be initiated normally, putting these participants at risk of losing their collaterals due to expulsion. This situation is unfair to the participants.

For example, let's say the `fixedCollateralEth` is set to 1 ETH. All participants, except for participants[0], have deposited only 1 ETH to the Collateral contract, while participants[0] has deposited 2 ETH. When the `initiateFundContract` function is called and the price of ETH decreases, the 1 ETH collateral will no longer be sufficient. Despite this, the function can still be executed normally, resulting in a fund cycle where all participants, except for participants[0], are at risk of being expelled.
#### Impact
This situation leads to unfair treatment of the participants based on their position in the list.
#### Code Snippet
https://github.com/TakafulDAO/takaturn/blob/6bb7a13ecb08aed08811239b963fac90b44e6ada/ethereum/contracts/Collateral.sol#L107-L108

#### Tool used
Manual Review

#### Recommendation
Should check the collateralization status of all participants in the `initiateFundContract` function.

---

## <a id="Low"></a>Low
### <a id="L01"></a> [L-01] Redundant conversion `address(msg.sender)`
#### Description 
`msg.sender` is already a `address` type, so we don't need to covert it to address. 

#### Code Snippet
https://github.com/TakafulDAO/takaturn/blob/6bb7a13ecb08aed08811239b963fac90b44e6ada/ethereum/contracts/Collateral.sol#L251
https://github.com/TakafulDAO/takaturn/blob/6bb7a13ecb08aed08811239b963fac90b44e6ada/ethereum/contracts/Collateral.sol#L263

#### Recommendation 
Modify `address(msg.sender)` to `msg.sender`

---

### <a id="L02"></a> [L-02] There is no need to initialize the value to 0
#### Description 
The default value of new stack `uint` variable is 0, so we don't need to initialize it to 0

#### Code Snippet
https://github.com/TakafulDAO/takaturn/blob/6bb7a13ecb08aed08811239b963fac90b44e6ada/ethereum/contracts/Fund.sol#L376

#### Recommendation 
Remove initialization to value 0 

--- 

### <a id="L03"></a> [L-03] Inconsistent use of `require` and `revert`
#### Description 
Across the smart contracts, some places use `request` and some places `revert`.

#### Code Snippet
Require: 
https://github.com/TakafulDAO/takaturn/blob/6bb7a13ecb08aed08811239b963fac90b44e6ada/ethereum/contracts/Fund.sol#L121-L123
https://github.com/TakafulDAO/takaturn/blob/6bb7a13ecb08aed08811239b963fac90b44e6ada/ethereum/contracts/Fund.sol#L167
https://github.com/TakafulDAO/takaturn/blob/6bb7a13ecb08aed08811239b963fac90b44e6ada/ethereum/contracts/Fund.sol#L200-L202
https://github.com/TakafulDAO/takaturn/blob/6bb7a13ecb08aed08811239b963fac90b44e6ada/ethereum/contracts/Fund.sol#L191
https://github.com/TakafulDAO/takaturn/blob/6bb7a13ecb08aed08811239b963fac90b44e6ada/ethereum/contracts/Fund.sol#L209-L211
https://github.com/TakafulDAO/takaturn/blob/6bb7a13ecb08aed08811239b963fac90b44e6ada/ethereum/contracts/Fund.sol#L218-L219
https://github.com/TakafulDAO/takaturn/blob/6bb7a13ecb08aed08811239b963fac90b44e6ada/ethereum/contracts/Fund.sol#L224
https://github.com/TakafulDAO/takaturn/blob/6bb7a13ecb08aed08811239b963fac90b44e6ada/ethereum/contracts/Fund.sol#L307-L308C16
Revert: 
https://github.com/TakafulDAO/takaturn/blob/6bb7a13ecb08aed08811239b963fac90b44e6ada/ethereum/contracts/Fund.sol#L231-L234

#### Recommendation 
I do recommend using `revert` with custom error to save gas

---
### <a id="L04"></a> [L-04] Should check if `contributionPeriod` is less than `cycleTime` in constructor of Fund contract
#### Description 
The `contributionPeriod` must be less than `cycleTime` (refer to [the docs](https://github.com/TakafulDAO/takaturn/blob/6bb7a13ecb08aed08811239b963fac90b44e6ada/ethereum/contracts/Fund.sol#L73)) to ensure the smooth flow of the funding cycle. Therefore, the constructor should verify this requirement.

#### Code Snippet
https://github.com/TakafulDAO/takaturn/blob/6bb7a13ecb08aed08811239b963fac90b44e6ada/ethereum/contracts/Fund.sol#L100

#### Recommendation 
Should add the requirement to constructor of Fund contract to esure `contributionPeriod` is less than `cycleTime`.

--- 
### <a id="L05"></a> [L-05] The `closeFundingPeriod` and `startNewCycle` functions should not restrict the caller to only the owner
#### Description 
The `closeFundingPeriod` and `startNewCycle` functions has a time-based condition that can impact the entire funding cycle if executed too late. To ensure the process and prevent mistakes, they should be executable by anyone instead of only the owner.

#### Code Snippet
https://github.com/TakafulDAO/takaturn/blob/6bb7a13ecb08aed08811239b963fac90b44e6ada/ethereum/contracts/Fund.sol#L114
https://github.com/TakafulDAO/takaturn/blob/6bb7a13ecb08aed08811239b963fac90b44e6ada/ethereum/contracts/Fund.sol#L119

#### Recommendation 
Should not utilize the `onlyOwner` modifier for `closeFundingPeriod` and `startNewCycle` functions

--- 