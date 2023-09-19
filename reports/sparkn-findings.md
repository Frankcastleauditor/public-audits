# Sparkn  - Findings Report

# Table of contents
- ## [Contest Summary](#contest-summary)
- ## [Results Summary](#results-summary)

- ## Medium Risk Findings
    - ### [M-01. If the STADIUM_ADDRESS got blacklisted by token contract, the fee and all the proxy functionality will be permanently frozen which lead to lock all the funds inside the proxy forever.](#M-01)
- ## Low Risk Findings
    - ### [L-01. mismatching the salt with the proxy allow the owner to distribute and take the tokens in the proxy before the EXPIRATION_TIME has finished , which cause loss of funds for the users](#L-01)
    - ### [L-02. allow sending rewards to the zero address will lead to lock the funds forever](#L-02)
    - ### [L-03. Executing a critical ownership transfer through a single-step process entails risks.](#L-03)
    - ### [L-04. using percentages mechanism to distribute the tokens limits the number of winners and prevents the organizer from distributing rewards to large number of users ](#L-04)
    - ### [L-05. misleading event can be emitted due to reward distribution within non-deployed proxy and may lead to loss of funds for the winners](#L-05)
    - ### [L-06. Some ERC20 tokens would revert on zero value transfers.](#L-06)
    - ### [L-07. ERC20 tokens with blackList can cause DoS attack and can prevent the #Distributor.sol contract from sending the rewards ](#L-07)


# <a id='contest-summary'></a>Contest Summary

### Sponsor: CodeFox Inc.

### Dates: Aug 21st, 2023 - Aug 29th, 2023

[See more contest details here](https://www.codehawks.com/contests/cllcnja1h0001lc08z7w0orxx)

# <a id='results-summary'></a>Results Summary

### Number of findings:
   - High: 0
   - Medium: 1
   - Low: 7



		
# Medium Risk Findings

## <a id='M-01'></a>M-01. If the STADIUM_ADDRESS got blacklisted by token contract, the fee and all the proxy functionality will be permanently frozen which lead to lock all the funds inside the proxy forever.            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-08-sparkn/blob/0f139b2dc53905700dd29a01451b330f829653e9/src/Distributor.sol#L164

## Summary
if the `STADIUM_ADDRESS` got blacklisted by the token it will be impossible to get the fee tokens from the proxy contract and all the functions of the proxy will be frozen and revert all time which will lead to a loss of funds for the protocol and users . 
 
## Vulnerability Details
Some tokens (e.g. USDC, USDT) have a contract level admin controlled address blocklist. If an address is blocked, then transfers to and from that address are forbidden , so if the `STADIUM_ADDRESS` get blocklisted for any reason this will lead to freeze all the functions the responsible for distribution of the reward which lead to lock all the funds and  fee tokens inside the proxy contract , which is a huge loss of funds . 

and if the protocol tried to deploy a new implementation contract ,all the locked funds will keep locked because the implementation can only be set once inside the proxy contract .  

# Poc 
in the Distributor contract, the function `distribute()` call the internal function `_commissionTransfer()` which send the fee tokens to the `STADIUM_ADDRESS` , as shown here
https://github.com/Cyfrin/2023-08-sparkn/blob/0f139b2dc53905700dd29a01451b330f829653e9/src/Distributor.sol#L116-L156 
```
    function _distribute(address token, address[] memory winners, uint256[] memory percentages, bytes memory data)
        internal
    {
        // token address input check
        if (token == address(0)) revert Distributor__NoZeroAddress();
        if (!_isWhiteListed(token)) {
            revert Distributor__InvalidTokenAddress();
        }
        // winners and percentages input check
        if (winners.length == 0 || winners.length != percentages.length) revert Distributor__MismatchedArrays();
        uint256 percentagesLength = percentages.length;
        uint256 totalPercentage;
        for (uint256 i; i < percentagesLength;) {
            totalPercentage += percentages[i];
            unchecked {
                ++i;
            }
        }
        // check if totalPercentage is correct
        if (totalPercentage != (10000 - COMMISSION_FEE)) {
            revert Distributor__MismatchedPercentages();
        }
        IERC20 erc20 = IERC20(token);
        uint256 totalAmount = erc20.balanceOf(address(this));


        // if there is no token to distribute, then revert
        if (totalAmount == 0) revert Distributor__NoTokenToDistribute();


        uint256 winnersLength = winners.length; // cache length
        for (uint256 i; i < winnersLength;) {
            uint256 amount = totalAmount * percentages[i] / BASIS_POINTS;
            erc20.safeTransfer(winners[i], amount);
            unchecked {
                ++i;
            }
        }


        // send commission fee as well as all the remaining tokens to STADIUM_ADDRESS to avoid dust remaining
  -->   _commissionTransfer(erc20);
        emit Distributed(token, winners, percentages, data);
    }
```
sending the fee tokens to the `STADIUM_ADDRESS` here : 
https://github.com/Cyfrin/2023-08-sparkn/blob/0f139b2dc53905700dd29a01451b330f829653e9/src/Distributor.sol#L163-L165
```
    function _commissionTransfer(IERC20 token) internal {
  -->    token.safeTransfer(STADIUM_ADDRESS, token.balanceOf(address(this)));
    }
```

if the function `_commissionTransfer()` reverts the `distribute()` will also revert which prevent the winners from getting their rewards and also prevent the owner from rescuing the tokens , which cause the all funds to be locked forever . 

## Impact
this vulnerability will  prevent the winners from getting their rewards , and the protocol from taking the fee ,and also prevent the owner from rescuing the tokens , which cause the all funds to be locked forever .
## Tools Used
manual review 
## Recommendations
there are two possible mitigation methods (the second is the favorable) :                                            
1)adding a function to set (change) the `implementation` inside the proxy and allow only the factory to call this function ,
and then add this function to the factory contract and allow only the owner to set the new implementation , and prevent all the other function in the factory from calling this `setImplemntation()` function , by reverting in case of the selector is the selector of this function  
add this function in the proxy 
```
function setImplementation(address newImpl) external  {
      if (msg.sender != FACTORY_ADDRESS) {
            revert Distributor__OnlyFactoryAddressIsAllowed();
        }
    implementation = newImpl ; 
} 
```
and this function in the factory 
```
function setImplementation(address newImpl) external onlyOwner {
     (bool success,) = proxy.call(abi.encodeWithSignture("setImplementation(address)" , newImpl));
}
```
2)add the `setImplementation` function in the proxy and allow only the owner of the factory contract to call it 
```
function setImplementation(address newImpl) external  {
      if (msg.sender != factoryOwner) {
            revert Distributor__OnlyFactoryOwnerIsAllowed();
        }
    implementation = newImpl ; 
} 
```

# Low Risk Findings

## <a id='L-01'></a>L-01. mismatching the salt with the proxy allow the owner to distribute and take the tokens in the proxy before the EXPIRATION_TIME has finished , which cause loss of funds for the users            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-08-sparkn/blob/0f139b2dc53905700dd29a01451b330f829653e9/src/ProxyFactory.sol#L205-L218

https://github.com/Cyfrin/2023-08-sparkn/blob/0f139b2dc53905700dd29a01451b330f829653e9/src/ProxyFactory.sol#L249-L253

## Summary
the owner can take the reward from the proxy before the `EXPIRATION_TIME` is passed . 
## Vulnerability Details
in the function `distributeByOwner()` the owner need to pass the `proxy` ,`organizer`, `contestId` , `implementation` , and `data` , and there is nothing prevent the owner from passing the `organizer`, `contestId` , `implementation` of one proxy and a different proxy as the parameter `proxy` , if the `salt` that is calculated in this function has smaller closetime than the `salt` that is used to deploy the `proxy` , this will allow the `owner` to get the reward (tokens) before the supposed time is passed  .
 the  function `distributeByOwner` call the internal function `_distribute()`  ,and then emit the event `event Distributed(address indexed proxy, bytes data);` , this will lead to loss of funds for the `organizer` and the `winners` .  

## Poc 
1)imagine that the owner set two different contests the first with `salt0` and the secound with `salt1` by calling the function `setContest()` twice .                                         
 2)the `salt0` has 100 seconds as `saltCloseTime0` and the `salt1` has 50 seconds as the `saltCloseTime1`.                                                                
  3)the `owner` call the function `distributeByOwner()` and pass `proxy0` that has been deployed by `salt0` and pass the rest of the parameters (`organizer`, `contestId` , `implementation`) that result in the `salt1` with the smaller `saltCloseTime`       
         4) finally the function will not revert since the check `(saltToCloseTime[salt] + EXPIRATION_TIME > block.timestamp)` will return `false` , and then call the internal `_distribute()` with `proxy0` and the owner will distribute the rewards as he wants although the `saltCloseTime0 + EXPIRATION_TIME` has not ended yet . 
# Poc2 
the test `testMismatchTheProxyWithSalt()` will pass successfully and the `owenr`  distributed the reward of the `proxy2` although the `CloseTime2` did not finished yet , the owner did it by using the `salt1` which is corresponding to much lower closeTime . 
- if you change the `contestId1` to be `contestId2` in the last ecternal call on the function `distributeByOwner()`  ,the test will revert .
```
contract test is Test {
    Distributor distributer;
    ProxyFactory factory;
    Proxy proxy;
    MockERC20 weth;

    address user1 = makeAddr("user1");
    address owner = makeAddr("owner");
    address user2 = makeAddr("user2");
    address organizer = makeAddr("organizer");
    address stadium = makeAddr("stadium");

    bytes32 contestId1 = 0x0000000000000000000000000000000000000000000000000000000000000001;
    bytes32 contestId2 = 0x0000000000000000000000000000000000000000000000000000000000000002;

    uint256 closeTime1;
    uint256 closeTime2;

    address[] whitelisedTokens = new address[](1);

    uint256 public constant EXPIRATION_TIME = 7 days;

    function setUp() external {
        weth = new MockERC20("Weth" , "WETH");
        whitelisedTokens[0] = address(weth);
        vm.prank(owner);
        factory = new ProxyFactory(whitelisedTokens);

        distributer = new Distributor(address(factory) , stadium);

        weth.mint(organizer, 100 * 10 ** 18);
    }

    function testMismatchTheProxyWithSalt() external {
        closeTime1 = block.timestamp + 1;
        closeTime2 = block.timestamp + 2 days;

        vm.startPrank(owner);
        factory.setContest(organizer, contestId1, closeTime1, address(distributer));
        factory.setContest(organizer, contestId2, closeTime2, address(distributer));

        bytes32 salt1 = _calculateSalt(organizer, contestId1, address(distributer));
        bytes32 salt2 = _calculateSalt(organizer, contestId2, address(distributer));

        address proxy1 = factory.getProxyAddress(salt1, address(distributer));
        address proxy2 = factory.getProxyAddress(salt2, address(distributer));

        vm.startPrank(organizer);
        weth.transfer(proxy1, 50 * 10 ** 18);
        weth.transfer(proxy2, 50 * 10 ** 18);

        vm.warp(closeTime1 + EXPIRATION_TIME + 1);
        vm.startPrank(owner);
        bytes memory data = createData();
        // this call should revert because the proxy2 the time of closeTime2 has not ended yet but this will not revert
        // supposed to revert but it will not revert
        // use the salt1 to distribute reward of the proxy2 , althought the close time has not passed 
        factory.distributeByOwner(proxy2, organizer, contestId1, address(distributer), data);
    }

    function _calculateSalt(address organizer11, bytes32 contestId, address implementation)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(organizer11, contestId, implementation));
    }

    function createData() public view returns (bytes memory data) {
        address[] memory winners = new address[](2);
        winners[0] = user1;
        winners[1] = user2;
        uint256[] memory percentages_ = new uint256[](2);
        percentages_[0] = 500;
        percentages_[1] = 9500 - 500;
        data = abi.encodeWithSelector(Distributor.distribute.selector, address(weth), winners, percentages_, "");
    }
}
```

## Impact
the owner can take or distribute the rewards as he wants before the `EXPIRATION_TIME + saltCloseTime` has passed , which will lead to loss of funds .  

## Tools Used
manual review 
## Recommendations
instead of taking `proxy` as a parameter from the owner , calculate the `proxy`address by calling the function `getProxyAddress()` and pass the `salt` ,that is calculated from the (`organizer`, `contestId` , `implementation`) by calling the function `_calculateSalt()`, and the `implementation` address , this will ensure that the `proxy` will always match the `salt` . 
```
    function distributeByOwner(
       -- 
        address organizer,
        bytes32 contestId,
        address implementation,
        bytes calldata data
    ) public onlyOwner {
        bytes32 salt = _calculateSalt(organizer, contestId, implementation);

     ++   address proxy = getProxyAddress(salt , implementation) ; 
        if (proxy == address(0)) revert ProxyFactory__ProxyAddressCannotBeZero();
        if (saltToCloseTime[salt] == 0) revert ProxyFactory__ContestIsNotRegistered();
        // distribute only when it exists and expired
        if (saltToCloseTime[salt] + EXPIRATION_TIME > block.timestamp) revert ProxyFactory__ContestIsNotExpired();
        _distribute(proxy, data);
    }
```

## <a id='L-02'></a>L-02. allow sending rewards to the zero address will lead to lock the funds forever            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-08-sparkn/blob/47c22b818818af4ea7388118dd83fa308ad67b83/src/Distributor.sol#L116-L151

https://github.com/Cyfrin/2023-08-sparkn/blob/47c22b818818af4ea7388118dd83fa308ad67b83/src/Distributor.sol#L92C4-L99

## Summary
allow sending funds to the address(0) during the distribution of the funds in `_distribute()` function 

## Vulnerability Details
the function `distribute()` take an array of `winners` as an input , 
```
 function distribute(address token, address[] memory winners, uint256[] memory percentages, bytes memory data)
```
and this function call the internal function `_distribute()` and pass the arrays of `winners` and `percentages` as parameters 
in the function `_distribute` there is no check for the validation of the address of the winners and this function does not prevent sending tokens to the zero address , the absent of this check may lead to the funds to be locked forever . 
```
    function _distribute(address token, address[] memory winners, uint256[] memory percentages, bytes memory data)
        internal
    {
        if (token == address(0)) revert Distributor__NoZeroAddress();
        if (!_isWhiteListed(token)) {
            revert Distributor__InvalidTokenAddress();
        }
        // winners and percentages input check
        if (winners.length == 0 || winners.length != percentages.length) revert Distributor__MismatchedArrays();
```

## Impact
the funds that are sent to the zero address will be locked forever . 
## Tools Used
manual review 
## Recommendations
add a check for the winners array inside the for loop to prevent passing the zero address as a winner. 
```
        for (uint256 i; i < percentagesLength;) {

     -->    if (winners[i] == address(0)) revert(); 

            totalPercentage += percentages[i];
            unchecked {
                ++i;
            }
        }
``` 
## <a id='L-03'></a>L-03. Executing a critical ownership transfer through a single-step process entails risks.            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-08-sparkn/blob/0f139b2dc53905700dd29a01451b330f829653e9/src/ProxyFactory.sol#L37

## Summary

The potential for human error makes the single-step critical ownership transfer process risky, as mistakes could lead to the unintended locking of all functions utilizing the onlyOwner modifier.
## Vulnerability Details

The Ownable.sol custom contract is inherited by proxyFactory.sol to incorporate ownable functionality. Presently, the implementation lacks safety because it involves a one-step process, which poses a risk due to potential human errors. Such errors can lead to irreversible consequences. For instance, there's a chance of mistakenly passing an incorrect address, which might lack a known associated private key.
## Impact
Critical functions using the onlyOwner modifier will be locked , such as setContest() and deployProxyAndDistributeByOwner().
## Tools Used
manual review 
## Recommendations

To ensure a more secure ownership change process and reduce potential risks, the following two-step approach can be implemented:

Step 1: Approval of Pending Ownership
Begin by designating a new address as the pendingOwner through a dedicated function. This step merely establishes the pending ownership without immediately effecting the change.

Step 2: Claiming Ownership Change
Once the pendingOwner address has been approved, the ownership change can be finalized. This involves the pendingOwner initiating a transaction to claim the ownership change. This step ensures that only after the correct address has been approved in step 1 can the ownership change be completed successfully in step 2. This way, the risk associated with errors is minimized, as incorrect addresses can be rectified during the initial approval step.






## <a id='L-04'></a>L-04. using percentages mechanism to distribute the tokens limits the number of winners and prevents the organizer from distributing rewards to large number of users             

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-08-sparkn/blob/0f139b2dc53905700dd29a01451b330f829653e9/src/Distributor.sol#L135-L137

https://github.com/Cyfrin/2023-08-sparkn/blob/0f139b2dc53905700dd29a01451b330f829653e9/src/Distributor.sol#L116-L151

https://github.com/Cyfrin/2023-08-sparkn/blob/0f139b2dc53905700dd29a01451b330f829653e9/src/ProxyFactory.sol#L127

## Summary
using the percentages to distribute the rewards limits the number of winners that can be used which will prevents the winners from getting their rewards , and can use Dos for the `distribute` function .
## Vulnerability Details
in the #Distributor contract
in order to the organizer distribute the rewards between the winners , he calls the function `deployProxyAndDistribute()` or `deployProxyAndDistributeBySignature()` and should pass two arrays `winners` and `percentages` , the sum of the values of the `percentages` arrays can not exceed `9500 bps` which is the result of `10_000 - COMMISSION_FEE ` which is equal to 10_000 - 500 = 9500 . 
The vulnerability arises due to the limitation of the number of the winners that can be rewarded , and there is no limits of the number of winners specified in the README. 
## POC
there are 2 scenarios this vulnerability can be happened :

1)if the organizer has e.g 8000 winners , and the first winner is given 1000 basis point from the `totalAmount` , which represents 10% , and the secound winner is given  another 1000 basis points , so the remaining basis points are : `10000 - 1000 -1000 -500(as fee) = 7500 basis points ` , so if the organizer wants to divide the remaining amount of the tokens in equal quantities between the remaining winners which are 7998 winners , so because of the minimun percentage of the winner is 1 , the function will revert because of the sum of the percentages is greater than 9500 ,which is  (10000 - COMMISSION_FEE), so this will prevent the winners from getting their rewards . 

2)if the organizer has number of winners is greater than 9500 , and want to distribute the reward in equal quantities between all the winners , this will lead to the reversion of the function because of the sum of percentages is greater than 9500 , so this will lead to prevent the winners from getting their rewards .
```
--> function _distribute(address token, address[] memory winners, uint256[] memory percentages, bytes memory data)
        internal
    {
        // token address input check
        if (token == address(0)) revert Distributor__NoZeroAddress();
        if (!_isWhiteListed(token)) {
            revert Distributor__InvalidTokenAddress();
        }
        // winners and percentages input check
        if (winners.length == 0 || winners.length != percentages.length) revert Distributor__MismatchedArrays();
        uint256 percentagesLength = percentages.length;
        uint256 totalPercentage;
        for (uint256 i; i < percentagesLength;) {
     -->    totalPercentage += percentages[i];
            unchecked {
                ++i;
            }
        }
```

the check that will cause the `_distribute()` function to revert :
```
        if (totalPercentage != (10000 - COMMISSION_FEE)) {
            revert Distributor__MismatchedPercentages();
        }
```
## Impact
this vulnerability will prevent the organizer from distributing the rewards to the winners , and cause the `_distribute()` function to always revert in this case , which is consider as loss of funds for the winners . 
 
## Tools Used
manual review 
## Recommendations
use a dynamic shares mechanism which allow the organizer to specify a number of shares for each user , and then calculate the sum of shares and cut the fee as a percentage form the total amount of tokens , so this will ensure an unlimited number of winners . 
## <a id='L-05'></a>L-05. misleading event can be emitted due to reward distribution within non-deployed proxy and may lead to loss of funds for the winners            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-08-sparkn/blob/0f139b2dc53905700dd29a01451b330f829653e9/src/ProxyFactory.sol#L205-L218

https://github.com/Cyfrin/2023-08-sparkn/blob/0f139b2dc53905700dd29a01451b330f829653e9/src/ProxyFactory.sol#L217

https://github.com/Cyfrin/2023-08-sparkn/blob/0f139b2dc53905700dd29a01451b330f829653e9/src/ProxyFactory.sol#L249-L253

## Summary
the event `Distributed(proxy, data);` will be emitted although there are no reward have been distributed ,and the winners are considered been rewarded . 
## Vulnerability Details
This vulnerability arises due to insufficient checks for the existence of the specified proxy contract before proceeding with the distribution.
in the function `distributeByOwner()` the owner can distribute the reward of any proxy after the `EXPIRATION_TIME` has passed , but in this function there is no check for the deployment of the proxy , and in the function `_distribute` there is an external call to the proxy contract by the low level call with keyword `call` **which will not revert if the contract had not been deployed before** , which will lead to the emission of the event and consider this reward is distributed . 
## Impact
this vulnerability will lead to misleading to any system that will be integrated with the proxyFactory contract or any frontend of the project , and this will lead to loss of funds for the winners that are assumed to get rewarded . 
## PoC 
1)imagine that the owner set a contest and get the `salt` .                            
2) the owner get the proxy address by calling the function `getProxyAddress()` which will returns the address even it has not been depolyed .                                                     
3) the owner call the function `distributeByOwner()` which will call the non-deployed proxy and will not revert . 
```
address notDeployedAddress = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 ; // a random address calculated from random salt 
(bool ok , ) = notDeployedAddress.call("");
if(!ok) revert();  
```    
this code will not revert 
4)the event `event Distributed(address indexed proxy, bytes data);` is emitted , and the frontend or the monitoring system assume that this proxy get deployed and distributed .                                  
5) the winners of that contest will be prevented from getting their rewards . 
## Tools Used
manual review and VScode . 
## Recommendations
add a check to make sure that the proxy has been deployed before the distribution of the reward . 
the check can be `mapping` from the proxy to `bool` :
```
mapping(address => bool ) public isDeployed ;  
```
and update this mapping every time the proxy get deployed and add the check in the function `_distribute` 
## <a id='L-06'></a>L-06. Some ERC20 tokens would revert on zero value transfers.            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-08-sparkn/blob/47c22b818818af4ea7388118dd83fa308ad67b83/src/Distributor.sol#L144-L150

https://github.com/Cyfrin/2023-08-sparkn/blob/47c22b818818af4ea7388118dd83fa308ad67b83/src/Distributor.sol#L147

https://github.com/Cyfrin/2023-08-sparkn/blob/47c22b818818af4ea7388118dd83fa308ad67b83/src/Distributor.sol#L116

## Summary
some ERC20 tokens revert on transfer 0 value and this will lead to DoS and prevent the winners from claiming their rewards 
## Vulnerability Details
some weird ERC20 revert on transfer of 0 value (e.g. `LEND`) ,can be found [here](https://github.com/d-xo/weird-erc20#revert-on-zero-value-transfers) 
in the function `_distribute()` the any `percentages` of the `winners` can be 0 value , and there is no check for the amount that will be sent to the winner , so the `amount` [here](https://github.com/Cyfrin/2023-08-sparkn/blob/47c22b818818af4ea7388118dd83fa308ad67b83/src/Distributor.sol#L147) can be zero which will lead to revert and the winners will not get their rewards 
```
        uint256 winnersLength = winners.length; // cache length
        for (uint256 i; i < winnersLength;) {
            uint256 amount = totalAmount * percentages[i] / BASIS_POINTS;
            erc20.safeTransfer(winners[i], amount);
            unchecked {
                ++i;
            }
```
## Impact
the reversion of the function will lead to loss of funds for the winners which will not get their rewards .
## Tools Used
manual review 
## Recommendations
make sure that the amount that will be sent is greater than zero and the percentage of the winner is greater than zero 
```
        uint256 winnersLength = winners.length; // cache length
        for (uint256 i; i < winnersLength;) {
-->  if (percentage[i] > 0 ) {

            uint256 amount = totalAmount * percentages[i] / BASIS_POINTS;
      -->    if (amount > 0 ) {
                  erc20.safeTransfer(winners[i], amount);
            unchecked {
                ++i;
            }
        }
    }
```
## <a id='L-07'></a>L-07. ERC20 tokens with blackList can cause DoS attack and can prevent the #Distributor.sol contract from sending the rewards             

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-08-sparkn/blob/47c22b818818af4ea7388118dd83fa308ad67b83/src/Distributor.sol#L116-L156

https://github.com/Cyfrin/2023-08-sparkn/blob/47c22b818818af4ea7388118dd83fa308ad67b83/src/Distributor.sol#L145-L150

https://github.com/Cyfrin/2023-08-sparkn/blob/47c22b818818af4ea7388118dd83fa308ad67b83/src/ProxyFactory.sol#L127-L138

## Summary

ERC20 tokens with blackList can prevent the Distributor contract form sending the reward to the winners . 

## Vulnerability Details

When distribution the `safeTransfer` of OpenZeppelin `SafeERC20Upgradeable` (inheriting from `SafeERC20`) is used which deals with the multiple ways in which different `ERC-20` (BEP-20) tokens indicate the success/failure of a token transfer.
Nevertheless, there is addition scenario that will prevent the all function from distributing the reward to the winners
 - the ERC20 tokens that are implementing a blacklist.
In this scenario, the reward token is implemented with a blacklist (also known as blocklist).
-DOS with the reward token being an ERC20-compatible ERC777 token as there is nothing says in the README that the ERC-777 token is not allowed to be used . 
 
Because this is common for tokens on the Ethereum network (e.g. USDC/USDT implementing blacklist/blocklist; See: https://github.com/d-xo/weird-erc20) this is a scenario also possible for the tokens . 
 
the DoS scenario if the reward token is ERC20 token that implements a blocklist can be : 
1) the winner is put in the token blacklist . 
2) the distributor try to send the rewards to the winners but this function always reverts , because of the users is on the blackList.
the DoS scenario if the reward token is an ERC20-compatible ERC777 token :
1) one of the winners acts as an "ERC777 recipient" which can either accept/reject tokens that are transferred to it . 
2) when the tokens get transferred to the malicious winner he will reject the token transfer as (ERC777 token calls tokensReceived function of receiving smart contract to finalize the token transfer which reverts)

the function `_distribute()` will revert during sending the funds to the winners . 
```
        uint256 winnersLength = winners.length; // cache length
        for (uint256 i; i < winnersLength;) {
            uint256 amount = totalAmount * percentages[i] / BASIS_POINTS;
            erc20.safeTransfer(winners[i], amount);
            unchecked {
                ++i;
            }
```

## Impact
the DoS prevent the winners from getting their reward which cause a loss of funds of the users.

## Tools Used
manual review 
## Recommendations
Use a withdrawal pattern ("pull over push") instead of directly send the reward to the winners. See: https://fravoll.github.io/solidity-patterns/pull_over_push.html for details. This way the function `_distribute()` will not get into a state of DOS.
by adding a function `withdraw` to allow the `winners` to claim their rewards , and creating a mapping from a winner to the balance 
```
mapping(address winner => uint256 balance ) public balances ; 
function withdraw(uint256 amount) external {
    balances [msg.sender] -= amount ;
    erc20.safeTransfer(msg.sender , amount); 
   }
```
