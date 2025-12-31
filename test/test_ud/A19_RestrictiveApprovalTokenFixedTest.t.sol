// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../src/RestrictiveApprovalTokenFixed.sol";

// Mock DeFi protocol that requires approval before balance
contract MockDeFiProtocol {
    RestrictiveApprovalTokenFixed public token;
    
    constructor(address _token) {
        token = RestrictiveApprovalTokenFixed(_token);
    }
    
    // Common DeFi pattern: approve before having balance
    function depositAndStake(uint256 amount) public {
        // User approves protocol first
        token.approve(address(this), amount);
        
        // Then deposits (mints) tokens
        token.mint(msg.sender, amount);
        
        // Then protocol can use the tokens
        // This pattern would fail with the vulnerable version
    }
}

// Mock DEX that requires pre-approval
contract MockDEX {
    RestrictiveApprovalTokenFixed public token;
    
    constructor(address _token) {
        token = RestrictiveApprovalTokenFixed(_token);
    }
    
    // Users approve max amount for gas efficiency
    function approveMaxForGasEfficiency(address user) public {
        // Approve max amount even before having balance
        // This is a common pattern for gas optimization
        token.approve(address(this), type(uint256).max);
    }
}

contract RestrictiveApprovalTokenFixedTest is Test {
    RestrictiveApprovalTokenFixed public token;
    
    address public user1;
    address public user2;
    address public spender;
    address public protocol;
    
    uint256 constant INITIAL_BALANCE = 10000 ether;
    uint256 constant APPROVAL_AMOUNT = 1000 ether;
    
    event Approval(address indexed owner, address indexed spender, uint256 value);
    
    function setUp() public {
        token = new RestrictiveApprovalTokenFixed();
        
        user1 = makeAddr("user1");
        user2 = makeAddr("user2");
        spender = makeAddr("spender");
        protocol = makeAddr("protocol");
        
        // Mint initial balances
        token.mint(user1, INITIAL_BALANCE);
        token.mint(user2, INITIAL_BALANCE);
    }
    
    // ==================== MINT TESTS ====================
    
    function test_Mint_IncreasesBalance() public {
        address recipient = makeAddr("recipient");
        uint256 amount = 500 ether;
        
        token.mint(recipient, amount);
        
        assertEq(token.balances(recipient), amount);
    }
    
    function test_Mint_MultipleTimesToSameAddress() public {
        address recipient = makeAddr("recipient");
        
        token.mint(recipient, 100 ether);
        token.mint(recipient, 200 ether);
        
        assertEq(token.balances(recipient), 300 ether);
    }
    
    function test_Mint_AnyoneCanMint() public {
        address recipient = makeAddr("recipient");
        
        vm.prank(user1);
        token.mint(recipient, 500 ether);
        
        assertEq(token.balances(recipient), 500 ether);
    }
    
    // ==================== APPROVE TESTS - BASIC FUNCTIONALITY ====================
    
    function test_Approve_Success() public {
        vm.expectEmit(true, true, false, true);
        emit Approval(user1, spender, APPROVAL_AMOUNT);
        
        vm.prank(user1);
        token.approve(spender, APPROVAL_AMOUNT);
        
        assertEq(token.allowance(user1, spender), APPROVAL_AMOUNT);
    }
    
    function test_Approve_EmitsEvent() public {
        vm.expectEmit(true, true, false, true);
        emit Approval(user1, spender, APPROVAL_AMOUNT);
        
        vm.prank(user1);
        token.approve(spender, APPROVAL_AMOUNT);
    }
    
    function test_Approve_OverwritesPreviousApproval() public {
        vm.startPrank(user1);
        
        token.approve(spender, 100 ether);
        assertEq(token.allowance(user1, spender), 100 ether);
        
        token.approve(spender, 200 ether);
        assertEq(token.allowance(user1, spender), 200 ether);
        
        vm.stopPrank();
    }
    
    function test_Approve_ZeroAmount() public {
        vm.startPrank(user1);
        
        // Set initial approval
        token.approve(spender, APPROVAL_AMOUNT);
        
        // Revoke approval by setting to zero
        token.approve(spender, 0);
        assertEq(token.allowance(user1, spender), 0);
        
        vm.stopPrank();
    }
    
    function test_Approve_MaxUint256() public {
        vm.prank(user1);
        token.approve(spender, type(uint256).max);
        
        assertEq(token.allowance(user1, spender), type(uint256).max);
    }
    
    function test_Approve_MultipleSpenders() public {
        address spender1 = makeAddr("spender1");
        address spender2 = makeAddr("spender2");
        address spender3 = makeAddr("spender3");
        
        vm.startPrank(user1);
        token.approve(spender1, 100 ether);
        token.approve(spender2, 200 ether);
        token.approve(spender3, 300 ether);
        vm.stopPrank();
        
        assertEq(token.allowance(user1, spender1), 100 ether);
        assertEq(token.allowance(user1, spender2), 200 ether);
        assertEq(token.allowance(user1, spender3), 300 ether);
    }
    
    // ==================== APPROVE TESTS - FIX VALIDATION ====================
    
    function test_Approve_WorksWithZeroBalance() public {
        // This is the KEY FIX: approve should work even with zero balance
        address newUser = makeAddr("newUser");
        
        // Verify user has zero balance
        assertEq(token.balances(newUser), 0);
        
        // User can still approve
        vm.prank(newUser);
        token.approve(spender, APPROVAL_AMOUNT);
        
        assertEq(token.allowance(newUser, spender), APPROVAL_AMOUNT);
    }
    
    function test_Approve_WorksWithInsufficientBalance() public {
        // User can approve more than they have
        address poorUser = makeAddr("poorUser");
        token.mint(poorUser, 100 ether);
        
        vm.prank(poorUser);
        token.approve(spender, 1000 ether); // Approve 10x more than balance
        
        assertEq(token.allowance(poorUser, spender), 1000 ether);
    }
    
    function test_Approve_BeforeMinting() public {
        // User approves before receiving tokens
        address futureHolder = makeAddr("futureHolder");
        
        // Approve first
        vm.prank(futureHolder);
        token.approve(spender, APPROVAL_AMOUNT);
        
        // Then mint
        token.mint(futureHolder, APPROVAL_AMOUNT);
        
        assertEq(token.allowance(futureHolder, spender), APPROVAL_AMOUNT);
        assertEq(token.balances(futureHolder), APPROVAL_AMOUNT);
    }
    
    function test_Approve_AfterSpendingAllTokens() public {
        vm.startPrank(user1);
        
        // Spend all tokens
        token.transfer(user2, INITIAL_BALANCE);
        assertEq(token.balances(user1), 0);
        
        // Can still approve
        token.approve(spender, APPROVAL_AMOUNT);
        assertEq(token.allowance(user1, spender), APPROVAL_AMOUNT);
        
        vm.stopPrank();
    }
    
    // ==================== DEFI PATTERN TESTS ====================
    
    function test_DeFiPattern_ApproveBeforeDeposit() public {
        // Common DeFi pattern: approve protocol before depositing
        address newUser = makeAddr("newUser");
        
        vm.startPrank(newUser);
        
        // Step 1: Approve protocol (before having tokens)
        token.approve(protocol, 500 ether);
        
        // Step 2: Receive tokens (e.g., from another user)
        vm.stopPrank();
        token.mint(newUser, 500 ether);
        
        // Verify approval is ready to use
        assertEq(token.allowance(newUser, protocol), 500 ether);
    }
    
    function test_DeFiPattern_MaxApprovalForGasEfficiency() public {
        // Users often approve max amount to save gas on future transactions
        address gasConscious = makeAddr("gasConscious");
        
        // Approve max even with zero balance
        vm.prank(gasConscious);
        token.approve(spender, type(uint256).max);
        
        assertEq(token.allowance(gasConscious, spender), type(uint256).max);
    }
    
    function test_DeFiPattern_PreApprovalForSmartContract() public {
        // Smart contracts often require pre-approval
        MockDeFiProtocol defi = new MockDeFiProtocol(address(token));
        
        address investor = makeAddr("investor");
        
        // Investor approves DeFi protocol first
        vm.prank(investor);
        token.approve(address(defi), 1000 ether);
        
        // Then can interact with protocol
        assertEq(token.allowance(investor, address(defi)), 1000 ether);
    }
    
    function test_DeFiPattern_MultiProtocolApprovals() public {
        // Users approve multiple protocols simultaneously
        address dex = makeAddr("dex");
        address lending = makeAddr("lending");
        address staking = makeAddr("staking");
        
        address investor = makeAddr("investor");
        
        vm.startPrank(investor);
        token.approve(dex, type(uint256).max);
        token.approve(lending, type(uint256).max);
        token.approve(staking, type(uint256).max);
        vm.stopPrank();
        
        assertEq(token.allowance(investor, dex), type(uint256).max);
        assertEq(token.allowance(investor, lending), type(uint256).max);
        assertEq(token.allowance(investor, staking), type(uint256).max);
    }
    
    // ==================== TRANSFER TESTS ====================
    
    function test_Transfer_Success() public {
        uint256 transferAmount = 100 ether;
        
        vm.prank(user1);
        token.transfer(user2, transferAmount);
        
        assertEq(token.balances(user1), INITIAL_BALANCE - transferAmount);
        assertEq(token.balances(user2), INITIAL_BALANCE + transferAmount);
    }
    
    function test_Transfer_RevertsOnInsufficientBalance() public {
        uint256 excessiveAmount = INITIAL_BALANCE + 1 ether;
        
        vm.prank(user1);
        vm.expectRevert();
        token.transfer(user2, excessiveAmount);
    }
    
    function test_Transfer_FullBalance() public {
        vm.prank(user1);
        token.transfer(user2, INITIAL_BALANCE);
        
        assertEq(token.balances(user1), 0);
        assertEq(token.balances(user2), INITIAL_BALANCE * 2);
    }
    
    function test_Transfer_ZeroAmount() public {
        vm.prank(user1);
        token.transfer(user2, 0);
        
        assertEq(token.balances(user1), INITIAL_BALANCE);
        assertEq(token.balances(user2), INITIAL_BALANCE);
    }
    
    function test_Transfer_ToSelf() public {
        vm.prank(user1);
        token.transfer(user1, 100 ether);
        
        // Balance should remain the same
        assertEq(token.balances(user1), INITIAL_BALANCE);
    }
    
    // ==================== INTEGRATION TESTS ====================
    
    function test_Integration_ApproveAndTransferWorkflow() public {
        // User approves while having balance
        vm.prank(user1);
        token.approve(spender, APPROVAL_AMOUNT);
        
        // Then transfers tokens
        vm.prank(user1);
        token.transfer(user2, 500 ether);
        
        // Approval should remain unchanged
        assertEq(token.allowance(user1, spender), APPROVAL_AMOUNT);
    }
    
    function test_Integration_TransferAllThenApprove() public {
        vm.startPrank(user1);
        
        // Transfer all balance
        token.transfer(user2, INITIAL_BALANCE);
        assertEq(token.balances(user1), 0);
        
        // Can still approve (this would fail in vulnerable version)
        token.approve(spender, APPROVAL_AMOUNT);
        assertEq(token.allowance(user1, spender), APPROVAL_AMOUNT);
        
        vm.stopPrank();
    }
    
    function test_Integration_MintApproveTransfer() public {
        address newUser = makeAddr("newUser");
        
        // Approve before having tokens
        vm.prank(newUser);
        token.approve(spender, 1000 ether);
        
        // Mint tokens
        token.mint(newUser, 1000 ether);
        
        // Transfer tokens
        vm.prank(newUser);
        token.transfer(user1, 500 ether);
        
        // Approval still valid
        assertEq(token.allowance(newUser, spender), 1000 ether);
        assertEq(token.balances(newUser), 500 ether);
    }
    
    // ==================== EDGE CASE TESTS ====================
    
    function test_EdgeCase_ApproveZeroAddress() public {
        vm.prank(user1);
        token.approve(address(0), APPROVAL_AMOUNT);
        
        assertEq(token.allowance(user1, address(0)), APPROVAL_AMOUNT);
    }
    
    function test_EdgeCase_MultipleApprovalsToSameSpender() public {
        vm.startPrank(user1);
        
        token.approve(spender, 100 ether);
        token.approve(spender, 200 ether);
        token.approve(spender, 300 ether);
        
        // Last approval wins
        assertEq(token.allowance(user1, spender), 300 ether);
        
        vm.stopPrank();
    }
    
    function test_EdgeCase_ApproveAfterRevoking() public {
        vm.startPrank(user1);
        
        // Approve
        token.approve(spender, APPROVAL_AMOUNT);
        
        // Revoke
        token.approve(spender, 0);
        
        // Approve again
        token.approve(spender, APPROVAL_AMOUNT * 2);
        
        assertEq(token.allowance(user1, spender), APPROVAL_AMOUNT * 2);
        
        vm.stopPrank();
    }
    
    function test_EdgeCase_IndependentAllowances() public {
        // user1 approves spender
        vm.prank(user1);
        token.approve(spender, 100 ether);
        
        // user2 approves spender
        vm.prank(user2);
        token.approve(spender, 200 ether);
        
        // Allowances are independent
        assertEq(token.allowance(user1, spender), 100 ether);
        assertEq(token.allowance(user2, spender), 200 ether);
    }
    
    // ==================== FUZZ TESTS ====================
    
    function testFuzz_Approve_AnyAmount(uint256 amount) public {
        vm.prank(user1);
        token.approve(spender, amount);
        
        assertEq(token.allowance(user1, spender), amount);
    }
    
    function testFuzz_Approve_WithAnyBalance(uint256 balance, uint256 approvalAmount) public {
        address user = makeAddr("fuzzUser");
        
        // Mint any balance
        if (balance > 0) {
            token.mint(user, balance);
        }
        
        // Should be able to approve any amount regardless of balance
        vm.prank(user);
        token.approve(spender, approvalAmount);
        
        assertEq(token.allowance(user, spender), approvalAmount);
    }
    
    function testFuzz_Approve_MultipleSpenders(address spender1, address spender2, uint256 amount1, uint256 amount2) public {
        vm.assume(spender1 != spender2);
        
        vm.startPrank(user1);
        token.approve(spender1, amount1);
        token.approve(spender2, amount2);
        vm.stopPrank();
        
        assertEq(token.allowance(user1, spender1), amount1);
        assertEq(token.allowance(user1, spender2), amount2);
    }
    
    function testFuzz_Transfer_WithinBalance(uint256 transferAmount) public {
        vm.assume(transferAmount <= INITIAL_BALANCE);
        
        vm.prank(user1);
        token.transfer(user2, transferAmount);
        
        assertEq(token.balances(user1), INITIAL_BALANCE - transferAmount);
        assertEq(token.balances(user2), INITIAL_BALANCE + transferAmount);
    }
    
    // ==================== GAS TESTS ====================
    
    function test_Gas_Approve() public {
        vm.prank(user1);
        uint256 gasBefore = gasleft();
        token.approve(spender, APPROVAL_AMOUNT);
        uint256 gasUsed = gasBefore - gasleft();
        
        emit log_named_uint("Gas used for approve", gasUsed);
    }
    
    function test_Gas_ApproveMax() public {
        vm.prank(user1);
        uint256 gasBefore = gasleft();
        token.approve(spender, type(uint256).max);
        uint256 gasUsed = gasBefore - gasleft();
        
        emit log_named_uint("Gas used for approve max", gasUsed);
    }
    
    function test_Gas_MultipleApprovals() public {
        uint256 totalGas = 0;
        
        vm.startPrank(user1);
        for (uint i = 0; i < 5; i++) {
            uint256 gasBefore = gasleft();
            token.approve(spender, i * 100 ether);
            totalGas += gasBefore - gasleft();
        }
        vm.stopPrank();
        
        emit log_named_uint("Total gas for 5 approvals", totalGas);
        emit log_named_uint("Average gas per approval", totalGas / 5);
    }
    
    // ==================== SECURITY FIX VALIDATION ====================
    
    function test_SecurityFix_ApproveWithZeroBalance() public {
        // This is the core security fix validation
        
        // OLD VULNERABLE VERSION would have:
        // require(balances[msg.sender] >= amount, "Insufficient balance");
        // This broke DeFi integrations
        
        // NEW FIXED VERSION:
        // No balance check, follows ERC20 standard
        
        address newUser = makeAddr("newUser");
        assertEq(token.balances(newUser), 0);
        
        // Should succeed (would fail in vulnerable version)
        vm.prank(newUser);
        token.approve(spender, 1000 ether);
        
        assertEq(token.allowance(newUser, spender), 1000 ether);
    }
    
    function test_SecurityFix_DeFiCompatibility() public {
        // Verify DeFi pattern compatibility
        
        address deFiUser = makeAddr("deFiUser");
        address deFiProtocol = makeAddr("deFiProtocol");
        
        vm.startPrank(deFiUser);
        
        // Step 1: User approves protocol (common first step)
        token.approve(deFiProtocol, type(uint256).max);
        
        // Step 2: User deposits into protocol (receives tokens)
        vm.stopPrank();
        token.mint(deFiUser, 1000 ether);
        
        // Step 3: Protocol can now use the tokens
        assertEq(token.allowance(deFiUser, deFiProtocol), type(uint256).max);
        assertEq(token.balances(deFiUser), 1000 ether);
    }
    
    function test_SecurityFix_ERC20StandardCompliance() public {
        // ERC20 standard does NOT require balance check in approve()
        // This test validates standard compliance
        
        address standardUser = makeAddr("standardUser");
        
        // User can approve without any balance (ERC20 compliant)
        vm.prank(standardUser);
        token.approve(spender, APPROVAL_AMOUNT);
        
        assertTrue(token.allowance(standardUser, spender) == APPROVAL_AMOUNT);
    }
    
    function test_SecurityFix_NoRevertOnLargeApproval() public {
        // Users should be able to approve more than they have
        address modestHolder = makeAddr("modestHolder");
        token.mint(modestHolder, 10 ether);
        
        // Approve way more than balance (should succeed)
        vm.prank(modestHolder);
        token.approve(spender, 10000 ether);
        
        assertEq(token.allowance(modestHolder, spender), 10000 ether);
    }
}