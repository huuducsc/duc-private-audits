# Goat Trading Security Review
###### tags: `private`, `GoatTrading`

A security review of the [Goat Trading](https://takadao.io/#) smart contract protocol was done by [duc](https://twitter.com/duc_hph) of [Trumpero](https://audits.sherlock.xyz/watson/Trumpero) team. \
This audit report includes all the vulnerabilities, issues and code improvements found during the security review.

# Disclaimer
A smart contract security review cannot assure the absolute absence of vulnerabilities. It involves a constrained allocation of time, resources, and expertise to identify as many vulnerabilities as possible. I cannot provide a guarantee of 100% security following the review, nor can I guarantee that any issues will be discovered during the review of your smart contracts.

# Severity Classification
## Severity
| **Severity** | **Impact: High** | **Impact: Medium** | **Impact: Low** |
|---|---|---|---|
| **Likelihood: High** | Critical  | High | Medium |  
| **Likelihood: Medium** | High | Medium | Low |   
| **Likelihood: Low** | Medium | Low | Low |   
## Impact 
**High** - leads to a significant material loss of assets in the protocol or significantly harms a group of users.

**Medium** - only a small amount of funds can be lost (such as leakage of value) or a core functionality of the protocol is affected.

**Low** - can lead to any kind of unexpected behaviour with some of the protocol's functionalities that's not so critical.

## Likelihood

**High** - attack path is possible with reasonable assumptions that mimic on-chain conditions, and the cost of the attack is relatively low compared to the amount of funds that can be stolen or lost.

**Medium** - only a conditionally incentivized attack vector, but still relatively likely.

**Low** - has too many or too unlikely assumptions or requires a significant stake by the attacker with little or no incentive.

# Audit scope
https://github.com/inedibleX/goat-trading/blob/main/contracts/



# Findings Summary 
| ID           | Title                                                                                                                                                        | Severity | Status  |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |  -------- | ------- |
| [C-01](#C01) | `tokenAmtForAmm` may be truncated to 0 due to division before multiplication during the calculation  | CRITICAL | Fixed |
| [C-02](#C02) | The liquidity provider of a pair can still transfer during the presale period to perform a sandwich attack and steal funds from the pair after it transitions to AMM | CRITICAL | Fixed |
| [H-01](#H01) | `_burnLiquidityAndConvertToAmm` will revert if the new liquidity exceeds the initial liquidity balance | HIGH | Fixed |
| [H-02](#H02) |  `takeOverPool` will result in the new balances of the pair contract not aligning with the new configurations if swaps occurred before  | HIGH     | Fixed |
| [H-03](#H03) | `takeOverPool()` function should be executed by a safety function in the GoatRouterV1 contract  | HIGH | Acknownledged |
| [M-01](#M01) |  The `takeOverPool` function is incompatible with Fee on Transfer tokens                   | MEDIUM     | Fixed |
| [M-02](#M02) |  Unexpected revert of addLiquidity function due to underflow risk                       | MEDIUM     | Fixed |
| [M-03](#M03) |  Attackers can mint tokens to prevent users from burning their liquidity    | MEDIUM   | Acknownledged |
| [M-04](#M04) |  Unable to take over the pool when _token is ERC777        | MEDIUM   | Acknownledged |
| [L-01](#L01) | The variables `initialTokenMatch` and `virtualEth` within the `GoatTypes.LocalVariables_Swap` struct are redundant | LOW      | Fixed |
| [L-02](#L02) | Use a value of 0 for initialEth in the function `_tokenAmountsForLiquidityBootstrap()` to save gas | LOW | Fixed |
| [L-03](#L03) | Redundant check in function `_checkAndConvertPool()` | LOW | Fixed |
| [L-04](#L04) | The use of braces in the virtual function is redundant  | LOW | Fixed |
| [L-05](#L05) | Redundant assertion in _addLiquidity function | LOW | Acknownledged |

# Detailed Findings

## <a id="Critical"></a>Critical

### <a id="C01"></a> [C-01] `tokenAmtForAmm` may be truncated to 0 due to division before multiplication during the calculation 
#### Description
In `_tokenAmountsForLiquidityBootstrap` function, `tokenAmtForAmm` is calculated as following: 
```solidity=
    uint256 k = virtualEth * initialTokenMatch;
    tokenAmtForAmm = ((k / (virtualEth + bootstrapEth)) / (virtualEth + bootstrapEth)) * bootstrapEth;
```
This calculation divides `k` by `virtualEth + bootstrapEth` before multiplication. Therefore, when `k` is less than `(virtualEth + bootstrapEth) ** 2`, tokenAmtForAmm will be 0.
This case may occur when `initialTokenMatch` is smaller than `(virtualEth + bootstrapEth) * (virtualEth + bootstrapEth) / virtualEth`. For example, when token is WBTC and 1 WBTC = 30 WETH, `virtualEth` is 300e18 and `initialTokenMatch` is 10e18, then `tokenAmtForAmm` will always be 0 for every bootstrapEth.

#### Impact
This issue results in a tokenAmtForAmm value of 0 during the first mint, which leads unfavorable states of this pair the during presale period and a token reserve of 0 after turning to AMM. After than, anyone can use WETH to swap and take profit, cause significant losses for the liquidity provider.

#### Code Snippet
* https://github.com/inedibleX/goat-trading/blob/main/contracts/exchange/GoatV1Pair.sol#L682
* https://github.com/inedibleX/goat-trading/blob/main/contracts/library/GoatLibrary.sol#L37
* https://github.com/inedibleX/goat-trading/blob/main/contracts/library/GoatLibrary.sol#L214

#### Recommendation
The calculation of tokenAmtForAmm should involve multiplication before division
```solidity=
tokenAmtForAmm = (k / (virtualEth + bootstrapEth))  * bootstrapEth / (virtualEth + bootstrapEth);
```
#### Discussion
Protocol team: fixed

---

### <a id="C02"></a> [C-02] The liquidity provider of a pair can still transfer during the presale period to perform a sandwich attack and steal funds from the pair after it transitions to AMM
#### Description
The liquidity provider of a pair is restricted to only being able to transfer to the address (pair) for burning their liquidity. They can transfer a maximum of 1/4 of the initial balance each time and need to wait 1 week thereafter. However, the contract still allows liquidity providers to transfer during the presale period (before the pair turns into AMM).
([`_beforeTokenTransfer`](https://github.com/inedibleX/goat-trading/blob/main/contracts/exchange/GoatV1Pair.sol#L699-L736) function)

When the pair successfully turns into AMM, it replaces the current liquidity balance of the liquidity provider with the new liquidity for the new reserves of the pair, in `_burnLiquidityAndConvertToAmm` function:
```solidity=
function _burnLiquidityAndConvertToAmm(uint256 actualEthReserve, uint256 actualTokenReserve) internal {
      address initialLiquidityProvider = _initialLPInfo.liquidityProvider;

      uint256 initialLPBalance = balanceOf(initialLiquidityProvider);

      uint256 liquidity = Math.sqrt(actualTokenReserve * actualEthReserve) - MINIMUM_LIQUIDITY;

      uint256 liquidityToBurn = initialLPBalance - liquidity;

      _updateInitialLpInfo(liquidity, 0, initialLiquidityProvider, false, true);
      _burn(initialLiquidityProvider, liquidityToBurn);
      _vestingUntil = uint32(block.timestamp + VESTING_PERIOD);
  }
```
The problem arises when the `initialLPBalance` can be much larger than the new liquidity due to the large values of `virtualEth` and `initialTokenAmount`. Therefore, if a liquidity provider transfers 1/4 of their initial balance before the pair transitions into AMM, this contract will hold the majority of the liquidity balance. This results in an unexpectedly inflated value of liquidity supply after transitioning into AMM, enabling the liquidity provider to execute a sandwich attack on the pair and burn a significant amount of liquidity shortly thereafter. In this case, the liquidity provider can withdraw the reserves of the pair without any waiting period.

A worse scenario arises when the liquidity provider can execute a sandwich attack on the `takeOverPool` function using this approach. After 2 days of the initial mint (the lock time of liquidity), if someone decides to take over the pool, the malicious liquidity provider (attacker) can perform a sandwich attack vector: the attacker transfers 1/4 of the liquidity balance to the pair's address -> a user executes `takeOverPool()` -> the attacker swaps to turn the pair into AMM and burn the transferred liquidity in the contract to claim almost of the new funds.

#### Impact
Liquidity provider can withdraw without waiting, the liquidity supply of the pair can be incorrectly inflated, and the new funds/reserves can be stolen.

#### Code Snippet
* https://github.com/inedibleX/goat-trading/blob/main/contracts/exchange/GoatV1Pair.sol#L699-L736
* https://github.com/inedibleX/goat-trading/blob/main/contracts/exchange/GoatV1Pair.sol#L634-L646

#### Recommendation
Don't allow liquidity provider to transfer before the pair turns into AMM.

#### Discussion
Protocol team: fixed

---

## <a id="High"></a>High

### <a id="H01"></a> [H-01] `_burnLiquidityAndConvertToAmm` will revert if the new liquidity exceeds the initial liquidity balance
#### Description
```solidity=
function _burnLiquidityAndConvertToAmm(uint256 actualEthReserve, uint256 actualTokenReserve) internal {
      address initialLiquidityProvider = _initialLPInfo.liquidityProvider;

      uint256 initialLPBalance = balanceOf(initialLiquidityProvider);

      uint256 liquidity = Math.sqrt(actualTokenReserve * actualEthReserve) - MINIMUM_LIQUIDITY;

      uint256 liquidityToBurn = initialLPBalance - liquidity;

      _updateInitialLpInfo(liquidity, 0, initialLiquidityProvider, false, true);
      _burn(initialLiquidityProvider, liquidityToBurn);
      _vestingUntil = uint32(block.timestamp + VESTING_PERIOD);
  }
```
Contract doesn't require `_bootstrapEth` to be smaller than `_virtualEth` in `initialize()`.
If `_bootstrapEth` is larger than `_virtualEth`, the new liquidity will exceed `initialLPBalance` in `_burnLiquidityAndConvertToAmm` function. This will cause this function to revert due to underflow then, preventing the pair from transitioning into AMM.
In this case, because initialLPBalance < liquidity,more liquidity should be minted to initialLiquidityProvider to archieve the expected balance.

#### Impact
Unexpected revert during swap, preventing the pair from transitioning into AMM.

#### Code Snippet
https://github.com/inedibleX/goat-trading/blob/main/contracts/exchange/GoatV1Pair.sol#L641

#### Recommendation
Should handle the case when the new liquidity > initialLPBalance  
```solidity=
If (initialLPBalance >= liquidity) {
    uint256 liquidityToBurn = initialLPBalance - liquidity;
    _burn(initialLiquidityProvider, liquidityToBurn);
} else {
    uint256 liquidityToMint = liquidity - initialLPBalance;
    _mint(initialLiquidityProvider, liquidityToMint);
}
_updateInitialLpInfo(liquidity, 0, initialLiquidityProvider, false, true);
```

#### Discussion
Protocol team: fixed

---

### <a id="H02"></a> [H-02] `takeOverPool` will result in the new balances of the pair contract not aligning with the new configurations if swaps occurred before
#### Description
In the takeOverPool function, it calculates the required tokens for the presale and AMM using the new configurations and the `initParams.initialEth`, which represents the initial ETH amount provided before, and then transfers this token amount to the contract:
```solidity=
(localVars.tokenAmountForPresaleNew, localVars.tokenAmountForAmmNew) = _tokenAmountsForLiquidityBootstrap(
    initParams.virtualEth, initParams.bootstrapEth, initParams.initialEth, initParams.initialTokenMatch
);

if (tokenAmount != (localVars.tokenAmountForPresaleNew + localVars.tokenAmountForAmmNew)) {
    revert GoatErrors.IncorrectTokenAmount();
}

IERC20(_token).safeTransferFrom(to, address(this), tokenAmount);
```
Afterwards, it transfers the exact initial ETH amount previously sent by the sender to the old liquidity provider, and transfers the initial token amount provided before (`tokenAmountForAmmOld` + `tokenAmountForPresaleOld`) from this contract to the old liquidity provider.

The problem is that the ETH actual reserves (`_reserveEth`) of this pool could be different from `initParams.initialEth` if any swaps occurred before `takeOverPool` transaction. It's similar with the actual reserve of token in this pool. Any swaps executed before this transaction were based on the old configurations of this pair (virtualEth, initialTokenMatch, etc.) during the presale period. Consequently, the swapped ETH amount and token amount may not align with the new configurations, leading to a mismatch between the current ETH actual reserve and the expected token amount according to the new configurations.
#### Impact
The new reserves of the pair contract will not align with the new configs after `takeOverPool`. This may lead to the new liquidity provider consuming more tokens than needed to reach enough bootstrap ETH after the pair rebalances, or the pair being unable to transition into AMM without any loss due to lack of tokens for rebalancing.
#### Code Snippet
https://github.com/inedibleX/goat-trading/blob/main/contracts/exchange/GoatV1Pair.sol#L463-L465
#### Recommendation
Calculate `localVars.tokenAmountForPresaleNew`, `localVars.tokenAmountForAmmNew` based on the current actual reserve of ETH (`_reserveEth`) instead of `initParams.initialEth`; check `tokenAmount` based on the initially provided token amount and the reserve of token (`_reserveToken`), as the following example:
```solidity=
(localVars.tokenAmountForPresaleNew, localVars.tokenAmountForAmmNew) = _tokenAmountsForLiquidityBootstrap(
    initParams.virtualEth, initParams.bootstrapEth, _reserveEth, initParams.initialTokenMatch
);

if (tokenAmount != (localVars.tokenAmountForPresaleNew + localVars.tokenAmountForAmmNew
                                  - localVars.tokenAmountForPresaleOld - localVars.tokenAmountForAmmOld + _reserveToken)) {
    revert GoatErrors.IncorrectTokenAmount();
}
```
#### Discussion
Protocol team: fixed

---

### <a id="H03"></a> [H-03] `takeOverPool()` function should be executed by a safety function in the GoatRouterV1 contract  
#### Description
GoatRouterV1 contract lacks a safety function to execute the takeOverPool function securely. 
There is a risk that the target pair of the `takeOverPool` transaction could be removed from the factory right before the transaction. This is because the `GoatV1Pair.withdrawExcessToken()` function can remove that pair from the factory, rendering it unused (see the code snippet).

#### Impact
The user may take over an unused pool, resulting in loss or waste of funds to recover

#### Code Snippet
https://github.com/inedibleX/goat-trading/blob/main/contracts/exchange/GoatV1Pair.sol#L404

#### Recommendation
GoatRouterV1 should have a safety function that checks the pools of the factory before executing the `takeOverPool()` function

#### Discussion
Protocol team: acknownledged

---
## <a id="Med"></a>Medium
### <a id="M01"></a> [M-01] The `takeOverPool` function is incompatible with Fee on Transfer tokens
#### Description
The `takeOverPool()` function necessitates the `to` address for sending an amount of `_token` equivalent to `tokenAmount = localVars.tokenAmountForPresaleNew + localVars.tokenAmountForAmmNew` to the pair.

```solidity=
if (tokenAmount != (localVars.tokenAmountForPresaleNew + localVars.tokenAmountForAmmNew)) {
    revert GoatErrors.IncorrectTokenAmount();
}

IERC20(_token).safeTransferFrom(to, address(this), tokenAmount);
```

However, if `_token` is a Fee on Transfer token, the pair contract will receive an amount less than `tokenAmount`, resulting in incorrect accounting for the presale amount and token for AMM.

#### Impact
The contract lacks sufficient tokens for the expected pair state.

#### Code Snippet
https://github.com/inedibleX/goat-trading/blob/b3349556530a49971d5ab5499691381ea384cb8e/contracts/exchange/GoatV1Pair.sol#L467-L471

#### Recommendation
Consider mandating the sender to transfer tokens before executing the function. This approach ensures that `tokenAmount` represents the difference between the current token balance of the pair and the pair's `_reserveToken`.

#### Discussion
Protocol team: fixed

---
### <a id="M02"></a> [M-02] Unexpected revert of addLiquidity function due to underflow risk
#### Description
`addLiquidity` function in GoatRouterV1 contract triggers `_ensurePoolAndPrepareLiqudityParameters` function, which calls `GoatLibrary.getActualBootstrapTokenAmount` to get the actual token amount used to mint in case of creating a new pair.
```solidity=
if (vars.isNewPair) {
    // only for the first time
    vars.wethAmount = initParams.initialEth;
    vars.actualTokenAmount = GoatLibrary.getActualBootstrapTokenAmount(
        initParams.virtualEth, initParams.bootstrapEth, vars.wethAmount, initParams.initialTokenMatch
    );
```
However, it may revert due to underflow risk in `_getTokenAmountsForPresaleAndAmm` function of GoatLibrary:
```solidity=
function _getTokenAmountsForPresaleAndAmm(
    uint256 virtualEth,
    uint256 bootstrapEth,
    uint256 initialEth,
    uint256 initialTokenMatch
) private pure returns (uint256 tokenAmtForPresale, uint256 tokenAmtForAmm) {
    uint256 k = virtualEth * initialTokenMatch;
    tokenAmtForPresale = initialTokenMatch - (k / (virtualEth + bootstrapEth));
    tokenAmtForAmm = ((k / (virtualEth + bootstrapEth)) / (virtualEth + bootstrapEth)) * bootstrapEth;

    if (initialEth != 0) {
        uint256 numerator = (initialEth * initialTokenMatch);
        uint256 denominator = virtualEth + initialEth;
        uint256 tokenAmountOut = numerator / denominator;
        tokenAmtForPresale -= tokenAmountOut;
    }
}
```
In this calculation:
```
tokenAmtForPresale = initialTokenMatch - (k / (virtualEth + bootstrapEth)) 
                   = initialTokenMatch * bootstrapEth / (virtualEth + bootstrapEth)
```
Therefore, when `initialEth` is larger than `bootstrapEth`, `tokenAmountOut` will be larger than `tokenAmtForPresale`, and it will revert due to underflow. However, in this scenario, `addLiquidity` function should use `bootstrapEth` amount of WETH to first mint into this pair instead of using `initialEth`.

#### Impact
Unexpected revert of `addLiquidity` function

#### Code Snippet
* https://github.com/inedibleX/goat-trading/blob/main/contracts/periphery/GoatRouterV1.sol#L292-L297
* https://github.com/inedibleX/goat-trading/blob/main/contracts/library/GoatLibrary.sol#L220

#### Recommendation
Use `vars.wethAmount` = `min(initParams.initialEth, bootstrapEth)` to initially mint into a new pair
```solidity=
if (vars.isNewPair) {
    // only for the first time
    vars.wethAmount = min(initParams.initialEth, bootstrapEth);
    vars.actualTokenAmount = GoatLibrary.getActualBootstrapTokenAmount(
        initParams.virtualEth, initParams.bootstrapEth, vars.wethAmount, initParams.initialTokenMatch
    );
```

#### Discussion
Protocol team: fixed

---
### <a id="M03"></a> [M-03] Attackers can mint tokens to prevent users from burning their liquidity
#### Description
The mapping `_locked` serves to indicate the earliest timestamp at which an address can execute a transfer. This functionality is confirmed within the `_beforeTokenTransfer()` function.

```solidity
function _beforeTokenTransfer(address from, address to, uint256 amount) internal override {
        ...
        if (_locked[from] > timestamp) {
            revert GoatErrors.LiquidityLocked();
        }
        ... 
}
```

The mapping's value is updated when the `mint(address to) -> _mint(address _to, uint256 _value)` function is invoked. However, a vulnerability arises as the `to` address can be arbitrarily specified by the function's caller. This flaw permits an attacker to mint a determined amount of liquidity tokens to users and increment their `_locked` mapping value. Consequently, the liquidity tokens of the victim become untransferrable to any address, including the pair contract itself, rendering them unable to burn their liquidity.

#### Impact
Users are unable to burn their liquidity tokens, leading to a freeze of funds.

#### Code Snippet
https://github.com/inedibleX/goat-trading/blob/b3349556530a49971d5ab5499691381ea384cb8e/contracts/exchange/GoatV1Pair.sol#L729-L731

#### Recommendation
Consider implementing a mechanism to allow users to whitelist addresses that can mint tokens for them.

#### Discussion
Protocol team: acknownledged

---
### <a id="M04"></a> [M-04] Unable to take over the pool when _token is ERC777
#### Description
Within the `takeOverPool()` function, the sender is mandated to transfer an amount of `_token` to the current initial liquidity provider. A complication arises when `_token` is an [ERC777](https://docs.openzeppelin.com/contracts/3.x/erc777), which is an ERC20 variant supporting callback hooks on each transfer. Leveraging this ERC777 feature, the initial liquidity provider can implement a callback function that reverts every `_token` transfer from other users to themselves. As a result, the transfer of `_token` within the `takeOverPool()` function will trigger a revert, causing the entire function to revert.

#### Impact
The inability to take over the pool occurs.

#### Code Snippet
https://github.com/inedibleX/goat-trading/blob/b3349556530a49971d5ab5499691381ea384cb8e/contracts/exchange/GoatV1Pair.sol#L487-L489

#### Recommendation
Consider establishing a new vesting contract within the `takeOverPool()` function and transferring the `_token` to this contract instead of directly transferring it to the initial liquidity provider. This vesting contract can then include a function allowing the initial liquidity provider to claim tokens from the contract.

#### Discussion
Protocol team: acknownledged

---
## <a id="Low"></a>Low
### <a id="L01"></a> [L-01] The variables `initialTokenMatch` and `virtualEth` within the `GoatTypes.LocalVariables_Swap` struct are redundant
#### Description
The variables `initialTokenMatch` and `virtualEth` are assigned values from the storage variables `_initialTokenMatch` and `_virtualEth` at lines [298-299](https://github.com/inedibleX/goat-trading/blob/b3349556530a49971d5ab5499691381ea384cb8e/contracts/exchange/GoatV1Pair.sol#L298-L299). However, these variables are not utilized anywhere in the subsequent code.

#### Code Snippet
https://github.com/inedibleX/goat-trading/blob/b3349556530a49971d5ab5499691381ea384cb8e/contracts/exchange/GoatV1Pair.sol#L298-L299

#### Recommendation
To conserve gas, consider removing these unused variables.

---

### <a id="L02"></a> [L-02] Use a value of 0 for initialEth in the function `_tokenAmountsForLiquidityBootstrap()` to save gas
#### Description
In the function `_tokenAmountsForLiquidityBootstrap()`, the input variable `initialEth` is used to modify the return value `tokenAmtForPresale` but doesn't affect the value of the variable `tokenAmtForAmm`. Consequently, when the logic only requires the value of `tokenAmtForAmm`, we can use the value 0 for `initialEth` to conserve gas.

#### Code Snippet
https://github.com/inedibleX/goat-trading/blob/b3349556530a49971d5ab5499691381ea384cb8e/contracts/exchange/GoatV1Pair.sol#L387-L388

#### Recommendation
Consider modifying the code at lines [387-388](https://github.com/inedibleX/goat-trading/blob/b3349556530a49971d5ab5499691381ea384cb8e/contracts/exchange/GoatV1Pair.sol#L387-L388) to:
```
(, uint256 tokenAmtForAmm) =
            _tokenAmountsForLiquidityBootstrap(_virtualEth, bootstrapEth, 0, _initialTokenMatch);
```

--- 

### <a id="L03"></a> [L-03] Redundant check in function `_checkAndConvertPool()`
#### Description
The function `_checkAndConvertPool()` can only be invoked within the `swap()` function under the following conditions:
1. The pool is in the presale period.
2. `swapVars.finalReserveEth` is greater than or equal to `swapVars.bootstrapEth`.

However, within the `_checkAndConvertPool()` function, the same check as condition 2 is redundantly implemented at line 651, resulting in unnecessary gas consumption.

#### Code Snippet
https://github.com/inedibleX/goat-trading/blob/b3349556530a49971d5ab5499691381ea384cb8e/contracts/exchange/GoatV1Pair.sol#L293  
https://github.com/inedibleX/goat-trading/blob/b3349556530a49971d5ab5499691381ea384cb8e/contracts/exchange/GoatV1Pair.sol#L651

#### Recommendation
Consider removing the if condition at line 651.

---
### <a id="L04"></a> [L-04] The use of braces in the virtual function is redundant
#### Description
The braces {} for the virtual function are unnecessary.

#### Code Snippet
https://github.com/inedibleX/goat-trading/blob/b3349556530a49971d5ab5499691381ea384cb8e/contracts/exchange/GoatV1ERC20.sol#L91-L93

#### Recommendation
Remove the braces {} if not necessary.

--- 
### <a id="L05"></a> [L-05] Redundant assertion in _addLiquidity function
#### Description
In `GoatRouterV1._addLiquidity()` function:
```solidity=
uint256 tokenAmountOptimal = GoatLibrary.quote(wethDesired, wethReserve, tokenReserve);
if (tokenAmountOptimal <= tokenDesired) {
   ...
} else {
    uint256 wethAmountOptimal = GoatLibrary.quote(tokenDesired, tokenReserve, wethReserve);
    assert(wethAmountOptimal <= wethDesired);
    ...
}
```
In case of tokenAmountOptimal > tokenDesired, it means wethDesired / wethReserve > tokenDesired / tokenReserve.
Therefore, the assertion `assert(wethAmountOptimal <= wethDesired);` is redundant.

### Code Snippet
https://github.com/inedibleX/goat-trading/blob/main/contracts/periphery/GoatRouterV1.sol#L268
### Recommendation
Remove this assertion

--- 
