*1. Approval Race Condition (Most Dangerous)

// Standard ERC-20 approve() function
function approve(address spender, uint256 amount) external returns (bool);

// Attack scenario:
// 1. User approves 100 tokens to spender (tx pending)
// 2. User changes mind, approves 50 tokens instead (tx sent)
// 3. Malicious spender sees both txs in mempool
// 4. Spender front-runs: uses 100 approval FIRST
// 5. THEN the 50 approval goes through
// Result: Spender still has 100 allowance!

**Solution 
    ```// Solution 1: Increase/decrease allowance pattern
function increaseAllowance(address spender, uint256 addedValue) external;
function decreaseAllowance(address spender, uint256 subtractedValue) external;

// Solution 2: SafeERC20 wrapper (OpenZeppelin)
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
using SafeERC20 for IERC20;
token.safeIncreaseAllowance(spender, amount);```
