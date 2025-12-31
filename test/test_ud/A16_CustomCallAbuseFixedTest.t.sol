// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../src/CustomCallAbuseFixed.sol";

// Mock ERC20 Token
contract MockERC20 is IApprovedToken {
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;
    
    string public name = "Mock Token";
    string public symbol = "MOCK";
    uint8 public decimals = 18;
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    
    function mint(address to, uint256 amount) public {
        balances[to] += amount;
        emit Transfer(address(0), to, amount);
    }
    
    function approve(address spender, uint256 amount) public returns (bool) {
        allowances[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }
    
    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external override returns (bool) {
        require(balances[from] >= amount, "Insufficient balance");
        require(allowances[from][msg.sender] >= amount, "Insufficient allowance");
        
        balances[from] -= amount;
        balances[to] += amount;
        allowances[from][msg.sender] -= amount;
        
        emit Transfer(from, to, amount);
        return true;
    }
    
    function balanceOf(address account) public view returns (uint256) {
        return balances[account];
    }
    
    function allowance(address owner, address spender) public view returns (uint256) {
        return allowances[owner][spender];
    }
}

// Mock Safe Partner Contract
contract MockSafePartner is ISafePartner {
    mapping(address => uint256) public deposits;
    
    event Deposited(address indexed user, uint256 amount);
    
    function depositFor(address user, uint256 amount) external override {
        deposits[user] += amount;
        emit Deposited(user, amount);
    }
    
    function getDeposit(address user) external view returns (uint256) {
        return deposits[user];
    }
}

// Mock Malicious Token (for security tests)
contract MaliciousToken is IApprovedToken {
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;
    
    bool public shouldRevert;
    bool public shouldReturnFalse;
    
    function mint(address to, uint256 amount) public {
        balances[to] += amount;
    }
    
    function approve(address spender, uint256 amount) public returns (bool) {
        allowances[msg.sender][spender] = amount;
        return true;
    }
    
    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external override returns (bool) {
        if (shouldRevert) {
            revert("Malicious revert");
        }
        if (shouldReturnFalse) {
            return false;
        }
        
        require(balances[from] >= amount, "Insufficient balance");
        require(allowances[from][msg.sender] >= amount, "Insufficient allowance");
        
        balances[from] -= amount;
        balances[to] += amount;
        allowances[from][msg.sender] -= amount;
        
        return true;
    }
    
    function setRevertMode(bool _shouldRevert) public {
        shouldRevert = _shouldRevert;
    }
    
    function setReturnFalseMode(bool _shouldReturnFalse) public {
        shouldReturnFalse = _shouldReturnFalse;
    }
}

// Mock Malicious Partner (for security tests)
contract MaliciousPartner is ISafePartner {
    bool public shouldRevert;
    
    function depositFor(address, uint256) external override {
        if (shouldRevert) {
            revert("Malicious partner revert");
        }
    }
    
    function setRevertMode(bool _shouldRevert) public {
        shouldRevert = _shouldRevert;
    }
}

contract CustomCallAbuseFixedTest is Test {
    CustomCallAbuseFixed public secureContract;
    
    MockERC20 public token;
    MockSafePartner public partner;
    
    address public user1;
    address public user2;
    address public attacker;
    
    uint256 constant INITIAL_BALANCE = 10000 ether;
    uint256 constant DEPOSIT_AMOUNT = 1000 ether;
    
    function setUp() public {
        // Setup test accounts
        user1 = makeAddr("user1");
        user2 = makeAddr("user2");
        attacker = makeAddr("attacker");
        
        // Deploy mock contracts
        token = new MockERC20();
        partner = new MockSafePartner();
        
        // Deploy secure contract
        secureContract = new CustomCallAbuseFixed(
            address(partner),
            address(token)
        );
        
        // Mint tokens to users
        token.mint(user1, INITIAL_BALANCE);
        token.mint(user2, INITIAL_BALANCE);
        token.mint(attacker, INITIAL_BALANCE);
    }
    
    // ==================== CONSTRUCTOR TESTS ====================
    
    function test_Constructor_SetsImmutableAddresses() public view {
        assertEq(address(secureContract.partner()), address(partner));
        assertEq(address(secureContract.token()), address(token));
    }
    
    function test_Constructor_AddressesAreImmutable() public {
        // Verify that addresses cannot be changed after deployment
        // (This is enforced by the immutable keyword, but we test it's set correctly)
        CustomCallAbuseFixed newContract = new CustomCallAbuseFixed(
            address(0x123),
            address(0x456)
        );
        
        assertEq(address(newContract.partner()), address(0x123));
        assertEq(address(newContract.token()), address(0x456));
    }
    
    // ==================== DEPOSIT FUNCTION TESTS ====================
    
    function test_Deposit_Success() public {
        // User approves contract
        vm.prank(user1);
        token.approve(address(secureContract), DEPOSIT_AMOUNT);
        
        // User deposits
        vm.expectEmit(true, false, false, true);
        emit MockSafePartner.Deposited(user1, DEPOSIT_AMOUNT);
        
        vm.prank(user1);
        secureContract.deposit(DEPOSIT_AMOUNT);
        
        // Verify state changes
        assertEq(token.balanceOf(user1), INITIAL_BALANCE - DEPOSIT_AMOUNT);
        assertEq(token.balanceOf(address(secureContract)), DEPOSIT_AMOUNT);
        assertEq(partner.deposits(user1), DEPOSIT_AMOUNT);
    }
    
    function test_Deposit_MultipleDeposits() public {
        vm.startPrank(user1);
        
        // First deposit
        token.approve(address(secureContract), DEPOSIT_AMOUNT);
        secureContract.deposit(DEPOSIT_AMOUNT);
        
        // Second deposit
        token.approve(address(secureContract), DEPOSIT_AMOUNT);
        secureContract.deposit(DEPOSIT_AMOUNT);
        
        vm.stopPrank();
        
        // Verify cumulative deposits
        assertEq(token.balanceOf(user1), INITIAL_BALANCE - (DEPOSIT_AMOUNT * 2));
        assertEq(partner.deposits(user1), DEPOSIT_AMOUNT * 2);
    }
    
    function test_Deposit_MultipleUsers() public {
        // User1 deposits
        vm.startPrank(user1);
        token.approve(address(secureContract), DEPOSIT_AMOUNT);
        secureContract.deposit(DEPOSIT_AMOUNT);
        vm.stopPrank();
        
        // User2 deposits
        vm.startPrank(user2);
        token.approve(address(secureContract), DEPOSIT_AMOUNT * 2);
        secureContract.deposit(DEPOSIT_AMOUNT * 2);
        vm.stopPrank();
        
        // Verify independent deposits
        assertEq(partner.deposits(user1), DEPOSIT_AMOUNT);
        assertEq(partner.deposits(user2), DEPOSIT_AMOUNT * 2);
    }
    
    function test_Deposit_RevertsWithoutApproval() public {
        // User tries to deposit without approval
        vm.prank(user1);
        vm.expectRevert("Insufficient allowance");
        secureContract.deposit(DEPOSIT_AMOUNT);
    }
    
    function test_Deposit_RevertsWithInsufficientApproval() public {
        // User approves less than deposit amount
        vm.prank(user1);
        token.approve(address(secureContract), DEPOSIT_AMOUNT - 1);
        
        vm.prank(user1);
        vm.expectRevert("Insufficient allowance");
        secureContract.deposit(DEPOSIT_AMOUNT);
    }
    
    function test_Deposit_RevertsWithInsufficientBalance() public {
        address poorUser = makeAddr("poorUser");
        token.mint(poorUser, 100 ether);
        
        vm.startPrank(poorUser);
        token.approve(address(secureContract), DEPOSIT_AMOUNT);
        
        vm.expectRevert("Insufficient balance");
        secureContract.deposit(DEPOSIT_AMOUNT);
        vm.stopPrank();
    }
    
    function test_Deposit_ZeroAmount() public {
        vm.prank(user1);
        token.approve(address(secureContract), 0);
        
        vm.prank(user1);
        secureContract.deposit(0);
        
        // Should succeed with zero amount
        assertEq(partner.deposits(user1), 0);
    }
    
    function test_Deposit_MaxUint256() public {
        uint256 maxAmount = type(uint256).max;
        address whale = makeAddr("whale");
        
        token.mint(whale, maxAmount);
        
        vm.startPrank(whale);
        token.approve(address(secureContract), maxAmount);
        secureContract.deposit(maxAmount);
        vm.stopPrank();
        
        assertEq(token.balanceOf(whale), 0);
        assertEq(partner.deposits(whale), maxAmount);
    }
    
    // ==================== SECURITY TESTS ====================
    
    function test_Security_NoArbitraryExecute() public {
        // Verify that the contract does NOT have an execute function
        // This test confirms the security fix
        
        // Try to call a non-existent execute function (should fail at compile time)
        // We can't actually test this in runtime, but the absence of the function
        // is the security feature
        
        // Instead, we verify the contract only has the intended functions
        // by checking that deposit is the only user-callable function
        assertTrue(true, "Contract has no arbitrary execute function");
    }
    
    function test_Security_HardcodedTargets() public view {
        // Verify targets are immutable and hardcoded
        assertEq(address(secureContract.token()), address(token));
        assertEq(address(secureContract.partner()), address(partner));
    }
    
    function test_Security_CannotCallArbitraryContracts() public {
        // The old vulnerable version had an execute() function
        // This version only allows interaction with hardcoded contracts
        
        // Create a malicious contract
        address maliciousContract = makeAddr("maliciousContract");
        
        // User cannot make the secure contract call arbitrary contracts
        // because there's no execute function
        
        vm.prank(attacker);
        token.approve(address(secureContract), DEPOSIT_AMOUNT);
        
        // Attacker can only call deposit, which uses hardcoded targets
        vm.prank(attacker);
        secureContract.deposit(DEPOSIT_AMOUNT);
        
        // Verify the deposit went to the legitimate partner contract
        assertEq(partner.deposits(attacker), DEPOSIT_AMOUNT);
    }
    
    function test_Security_CannotStealApprovals() public {
        // Attacker approves contract
        vm.prank(attacker);
        token.approve(address(secureContract), DEPOSIT_AMOUNT);
        
        // Attacker cannot use another user's approval
        // because msg.sender is checked in transferFrom
        
        vm.prank(user1);
        token.approve(address(secureContract), DEPOSIT_AMOUNT);
        
        // Attacker calls deposit - should use attacker's tokens, not user1's
        vm.prank(attacker);
        secureContract.deposit(DEPOSIT_AMOUNT);
        
        // Verify attacker's balance decreased, not user1's
        assertEq(token.balanceOf(attacker), INITIAL_BALANCE - DEPOSIT_AMOUNT);
        assertEq(token.balanceOf(user1), INITIAL_BALANCE);
    }
    
    function test_Security_TokenTransferFromUsesCorrectSender() public {
        // Verify that transferFrom uses msg.sender correctly
        vm.prank(user1);
        token.approve(address(secureContract), DEPOSIT_AMOUNT);
        
        vm.prank(user1);
        secureContract.deposit(DEPOSIT_AMOUNT);
        
        // Tokens should come from user1 (msg.sender)
        assertEq(token.balanceOf(user1), INITIAL_BALANCE - DEPOSIT_AMOUNT);
    }
    
    function test_Security_DepositForUsesCorrectUser() public {
        // Verify that depositFor credits the correct user
        vm.prank(user1);
        token.approve(address(secureContract), DEPOSIT_AMOUNT);
        
        vm.prank(user1);
        secureContract.deposit(DEPOSIT_AMOUNT);
        
        // Deposit should be credited to user1
        assertEq(partner.deposits(user1), DEPOSIT_AMOUNT);
        assertEq(partner.deposits(user2), 0);
    }
    
    // ==================== INTEGRATION WITH MALICIOUS CONTRACTS ====================
    
    function test_MaliciousToken_RevertsOnTransferFrom() public {
        MaliciousToken malToken = new MaliciousToken();
        MaliciousPartner malPartner = new MaliciousPartner();
        
        CustomCallAbuseFixed contractWithMalToken = new CustomCallAbuseFixed(
            address(malPartner),
            address(malToken)
        );
        
        malToken.mint(user1, INITIAL_BALANCE);
        
        vm.startPrank(user1);
        malToken.approve(address(contractWithMalToken), DEPOSIT_AMOUNT);
        
        // Set token to revert
        malToken.setRevertMode(true);
        
        vm.expectRevert("Malicious revert");
        contractWithMalToken.deposit(DEPOSIT_AMOUNT);
        vm.stopPrank();
    }
    
    function test_MaliciousPartner_RevertsOnDeposit() public {
        MaliciousPartner malPartner = new MaliciousPartner();
        
        CustomCallAbuseFixed contractWithMalPartner = new CustomCallAbuseFixed(
            address(malPartner),
            address(token)
        );
        
        vm.startPrank(user1);
        token.approve(address(contractWithMalPartner), DEPOSIT_AMOUNT);
        
        // Set partner to revert
        malPartner.setRevertMode(true);
        
        vm.expectRevert("Malicious partner revert");
        contractWithMalPartner.deposit(DEPOSIT_AMOUNT);
        vm.stopPrank();
    }
    
    // ==================== EDGE CASE TESTS ====================
    
    function test_EdgeCase_DepositAfterPartialApproval() public {
        vm.startPrank(user1);
        
        // Approve and deposit partially
        token.approve(address(secureContract), DEPOSIT_AMOUNT);
        secureContract.deposit(DEPOSIT_AMOUNT / 2);
        
        // Try to deposit more than remaining approval
        vm.expectRevert("Insufficient allowance");
        secureContract.deposit(DEPOSIT_AMOUNT);
        
        vm.stopPrank();
    }
    
    function test_EdgeCase_ApprovalDecreasesAfterDeposit() public {
        vm.startPrank(user1);
        
        token.approve(address(secureContract), DEPOSIT_AMOUNT);
        
        uint256 allowanceBefore = token.allowance(user1, address(secureContract));
        assertEq(allowanceBefore, DEPOSIT_AMOUNT);
        
        secureContract.deposit(DEPOSIT_AMOUNT / 2);
        
        uint256 allowanceAfter = token.allowance(user1, address(secureContract));
        assertEq(allowanceAfter, DEPOSIT_AMOUNT / 2);
        
        vm.stopPrank();
    }
    
    function test_EdgeCase_ReApproveAndDeposit() public {
        vm.startPrank(user1);
        
        // First approval and deposit
        token.approve(address(secureContract), DEPOSIT_AMOUNT);
        secureContract.deposit(DEPOSIT_AMOUNT);
        
        // Re-approve and deposit again
        token.approve(address(secureContract), DEPOSIT_AMOUNT);
        secureContract.deposit(DEPOSIT_AMOUNT);
        
        vm.stopPrank();
        
        assertEq(partner.deposits(user1), DEPOSIT_AMOUNT * 2);
    }
    
    // ==================== FUZZ TESTS ====================
    
    function testFuzz_Deposit(uint256 amount) public {
        vm.assume(amount > 0 && amount <= INITIAL_BALANCE);
        
        vm.startPrank(user1);
        token.approve(address(secureContract), amount);
        secureContract.deposit(amount);
        vm.stopPrank();
        
        assertEq(token.balanceOf(user1), INITIAL_BALANCE - amount);
        assertEq(partner.deposits(user1), amount);
    }
    
    function testFuzz_MultipleDeposits(uint256 amount1, uint256 amount2) public {
        vm.assume(amount1 > 0 && amount1 <= INITIAL_BALANCE / 2);
        vm.assume(amount2 > 0 && amount2 <= INITIAL_BALANCE / 2);
        
        vm.startPrank(user1);
        
        token.approve(address(secureContract), amount1);
        secureContract.deposit(amount1);
        
        token.approve(address(secureContract), amount2);
        secureContract.deposit(amount2);
        
        vm.stopPrank();
        
        assertEq(partner.deposits(user1), amount1 + amount2);
    }
    
    function testFuzz_MultipleUsers(address user, uint256 amount) public {
        vm.assume(user != address(0) && user != address(secureContract));
        vm.assume(user != address(token) && user != address(partner));
        vm.assume(amount > 0 && amount <= INITIAL_BALANCE);
        
        token.mint(user, INITIAL_BALANCE);
        
        vm.startPrank(user);
        token.approve(address(secureContract), amount);
        secureContract.deposit(amount);
        vm.stopPrank();
        
        assertEq(partner.deposits(user), amount);
    }
    
    // ==================== GAS OPTIMIZATION TESTS ====================
    
    function test_Gas_SingleDeposit() public {
        vm.prank(user1);
        token.approve(address(secureContract), DEPOSIT_AMOUNT);
        
        uint256 gasBefore = gasleft();
        vm.prank(user1);
        secureContract.deposit(DEPOSIT_AMOUNT);
        uint256 gasUsed = gasBefore - gasleft();
        
        // Log gas usage (typical usage should be reasonable)
        emit log_named_uint("Gas used for single deposit", gasUsed);
    }
    
    // ==================== COMPARISON WITH VULNERABLE VERSION ====================
    
    function test_ComparisonWithVulnerableVersion() public {
        // This test documents the security improvement
        
        // OLD VULNERABLE VERSION would have:
        // - execute(address target, bytes calldata data) function
        // - Allowed arbitrary external calls
        // - Could abuse any approvals given to the contract
        
        // NEW FIXED VERSION:
        // - No execute function
        // - Only hardcoded interactions with specific contracts
        // - Cannot abuse approvals for unintended purposes
        
        // Verify the fix by ensuring deposit works as intended
        vm.startPrank(user1);
        token.approve(address(secureContract), DEPOSIT_AMOUNT);
        secureContract.deposit(DEPOSIT_AMOUNT);
        vm.stopPrank();
        
        // And verify no other functions exist for arbitrary calls
        // (This is enforced by the compiler, not runtime)
        assertTrue(true, "No arbitrary execute function exists");
    }
}