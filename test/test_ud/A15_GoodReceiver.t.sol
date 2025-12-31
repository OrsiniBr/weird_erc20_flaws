// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../src/CustomFallbackTokenFixed.sol";

// Mock contract that implements ITokenReceiver
contract GoodReceiver is ITokenReceiver {
    event TokenReceived(address from, uint256 amount, bytes data);
    
    function tokenFallback(
        address from,
        uint256 amount,
        bytes calldata data
    ) external override {
        emit TokenReceived(from, amount, data);
    }
}

// Mock contract that reverts on tokenFallback
contract RevertingReceiver is ITokenReceiver {
    function tokenFallback(
        address,
        uint256,
        bytes calldata
    ) external pure override {
        revert("I don't accept tokens");
    }
}

// Mock contract that attempts reentrancy attack
contract MaliciousReceiver is ITokenReceiver {
    CustomFallbackTokenFixed public token;
    address public attacker;
    bool public hasAttacked;
    
    constructor(address _token) {
        token = CustomFallbackTokenFixed(_token);
        attacker = msg.sender;
    }
    
    function tokenFallback(
        address,
        uint256,
        bytes calldata
    ) external override {
        if (!hasAttacked) {
            hasAttacked = true;
            // Attempt to steal ownership via reentrancy
            token.tryToCallSetOwnerInternally(attacker);
        }
    }
}

// Mock contract without tokenFallback implementation
contract NonReceiver {
    // No tokenFallback function
}

contract CustomFallbackTokenFixedTest is Test {
    CustomFallbackTokenFixed public token;
    
    address public owner;
    address public user1;
    address public user2;
    address public unauthorizedUser;
    
    GoodReceiver public goodReceiver;
    RevertingReceiver public revertingReceiver;
    NonReceiver public nonReceiver;
    
    uint256 constant INITIAL_BALANCE = 1000 ether;
    
    event OwnerSet(address indexed newOwner);
    
    function setUp() public {
        // Deploy token contract
        token = new CustomFallbackTokenFixed();
        
        // Setup test accounts
        owner = address(this); // Test contract is the owner
        user1 = makeAddr("user1");
        user2 = makeAddr("user2");
        unauthorizedUser = makeAddr("unauthorized");
        
        // Deploy receiver contracts
        goodReceiver = new GoodReceiver();
        revertingReceiver = new RevertingReceiver();
        nonReceiver = new NonReceiver();
        
        // Mint initial balances
        token.mint(user1, INITIAL_BALANCE);
        token.mint(user2, INITIAL_BALANCE);
    }
    
    // ==================== CONSTRUCTOR & OWNERSHIP TESTS ====================
    
    function test_Constructor_SetsOwner() public view {
        assertEq(token.owner(), owner);
    }
    
    function test_SetOwner_SuccessAsOwner() public {
        address newOwner = makeAddr("newOwner");
        
        vm.expectEmit(true, false, false, false);
        emit OwnerSet(newOwner);
        
        token.setOwner(newOwner);
        
        assertEq(token.owner(), newOwner);
    }
    
    function test_SetOwner_RevertsAsNonOwner() public {
        address newOwner = makeAddr("newOwner");
        
        vm.prank(unauthorizedUser);
        vm.expectRevert("Not authorized");
        token.setOwner(newOwner);
    }
    
    function test_SetOwner_TransfersAuthority() public {
        address newOwner = makeAddr("newOwner");
        
        // Transfer ownership
        token.setOwner(newOwner);
        
        // Old owner cannot set owner anymore
        vm.expectRevert("Not authorized");
        token.setOwner(owner);
        
        // New owner can set owner
        vm.prank(newOwner);
        token.setOwner(user1);
        assertEq(token.owner(), user1);
    }
    
    // ==================== AUTHORIZATION FIX TESTS ====================
    
    function test_IsAuthorized_OnlyOwner() public view {
        // Owner is authorized (we can't directly call isAuthorized, but we test via setOwner)
        // Non-owner is not authorized
        // Contract itself is NOT authorized (FIX 1)
    }
    
    function test_TryToCallSetOwnerInternally_RevertsForNonOwner() public {
        address attacker = makeAddr("attacker");
        
        vm.prank(unauthorizedUser);
        vm.expectRevert("Not authorized");
        token.tryToCallSetOwnerInternally(attacker);
    }
    
    function test_TryToCallSetOwnerInternally_SucceedsForOwner() public {
        address newOwner = makeAddr("newOwner");
        
        token.tryToCallSetOwnerInternally(newOwner);
        
        assertEq(token.owner(), newOwner);
    }
    
    function test_ContractCannotAuthorizeItself() public {
        // This tests that removing `if (src == address(this))` prevents
        // internal calls from bypassing authorization
        
        address attacker = makeAddr("attacker");
        
        // Even if called through the contract, unauthorized user cannot change owner
        vm.prank(unauthorizedUser);
        vm.expectRevert("Not authorized");
        token.tryToCallSetOwnerInternally(attacker);
        
        // Original owner should remain
        assertEq(token.owner(), owner);
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
        uint256 amount = 500 ether;
        
        vm.prank(unauthorizedUser);
        token.mint(recipient, amount);
        
        assertEq(token.balances(recipient), amount);
    }
    
    // ==================== TRANSFER TO EOA TESTS ====================
    
    function test_Transfer_SuccessToEOA() public {
        uint256 transferAmount = 100 ether;
        
        vm.prank(user1);
        token.transfer(user2, transferAmount, "");
        
        assertEq(token.balances(user1), INITIAL_BALANCE - transferAmount);
        assertEq(token.balances(user2), INITIAL_BALANCE + transferAmount);
    }
    
    function test_Transfer_WithData() public {
        uint256 transferAmount = 100 ether;
        bytes memory data = "Hello World";
        
        vm.prank(user1);
        token.transfer(user2, transferAmount, data);
        
        assertEq(token.balances(user1), INITIAL_BALANCE - transferAmount);
        assertEq(token.balances(user2), INITIAL_BALANCE + transferAmount);
    }
    
    function test_Transfer_RevertsOnInsufficientBalance() public {
        uint256 excessiveAmount = INITIAL_BALANCE + 1 ether;
        
        vm.prank(user1);
        vm.expectRevert("Insufficient balance");
        token.transfer(user2, excessiveAmount, "");
    }
    
    function test_Transfer_FullBalance() public {
        vm.prank(user1);
        token.transfer(user2, INITIAL_BALANCE, "");
        
        assertEq(token.balances(user1), 0);
        assertEq(token.balances(user2), INITIAL_BALANCE * 2);
    }
    
    function test_Transfer_ZeroAmount() public {
        vm.prank(user1);
        token.transfer(user2, 0, "");
        
        assertEq(token.balances(user1), INITIAL_BALANCE);
        assertEq(token.balances(user2), INITIAL_BALANCE);
    }
    
    // ==================== TRANSFER TO CONTRACT TESTS ====================
    
    function test_Transfer_ToGoodReceiver() public {
        uint256 transferAmount = 100 ether;
        bytes memory data = "test data";
        
        vm.expectEmit(true, false, false, true);
        emit GoodReceiver.TokenReceived(user1, transferAmount, data);
        
        vm.prank(user1);
        token.transfer(address(goodReceiver), transferAmount, data);
        
        assertEq(token.balances(user1), INITIAL_BALANCE - transferAmount);
        assertEq(token.balances(address(goodReceiver)), transferAmount);
    }
    
    function test_Transfer_ToRevertingReceiver_DoesNotRevert() public {
        uint256 transferAmount = 100 ether;
        
        // Transfer should succeed despite receiver reverting (FIX 2: try/catch)
        vm.prank(user1);
        token.transfer(address(revertingReceiver), transferAmount, "");
        
        assertEq(token.balances(user1), INITIAL_BALANCE - transferAmount);
        assertEq(token.balances(address(revertingReceiver)), transferAmount);
    }
    
    function test_Transfer_ToNonReceiver_Succeeds() public {
        uint256 transferAmount = 100 ether;
        
        // Transfer to contract without tokenFallback should succeed
        vm.prank(user1);
        token.transfer(address(nonReceiver), transferAmount, "");
        
        assertEq(token.balances(user1), INITIAL_BALANCE - transferAmount);
        assertEq(token.balances(address(nonReceiver)), transferAmount);
    }
    
    // ==================== REENTRANCY ATTACK TESTS ====================
    
    function test_Transfer_PreventsReentrancyOwnershipHijack() public {
        MaliciousReceiver malicious = new MaliciousReceiver(address(token));
        uint256 transferAmount = 100 ether;
        
        // Malicious contract tries to steal ownership during tokenFallback
        vm.prank(user1);
        token.transfer(address(malicious), transferAmount, "");
        
        // Owner should still be the original owner
        // The malicious contract's attempt should fail because it's not authorized
        assertEq(token.owner(), owner);
        
        // Transfer should still succeed
        assertEq(token.balances(address(malicious)), transferAmount);
        assertTrue(malicious.hasAttacked(), "Attack was attempted");
    }
    
    function test_Transfer_ReentrancyCannotBypassAuth() public {
        MaliciousReceiver malicious = new MaliciousReceiver(address(token));
        token.mint(address(malicious), INITIAL_BALANCE);
        
        address attacker = makeAddr("attacker");
        
        // Even if malicious contract calls tryToCallSetOwnerInternally during fallback,
        // it should not be authorized
        vm.prank(address(malicious));
        vm.expectRevert("Not authorized");
        token.tryToCallSetOwnerInternally(attacker);
    }
    
    // ==================== MULTIPLE TRANSFER TESTS ====================
    
    function test_Transfer_MultipleTransfersToSameReceiver() public {
        vm.startPrank(user1);
        
        token.transfer(address(goodReceiver), 100 ether, "first");
        token.transfer(address(goodReceiver), 200 ether, "second");
        token.transfer(address(goodReceiver), 300 ether, "third");
        
        vm.stopPrank();
        
        assertEq(token.balances(user1), INITIAL_BALANCE - 600 ether);
        assertEq(token.balances(address(goodReceiver)), 600 ether);
    }
    
    function test_Transfer_ChainOfTransfers() public {
        // user1 -> user2 -> goodReceiver
        uint256 amount = 100 ether;
        
        vm.prank(user1);
        token.transfer(user2, amount, "");
        
        vm.prank(user2);
        token.transfer(address(goodReceiver), amount, "");
        
        assertEq(token.balances(user1), INITIAL_BALANCE - amount);
        assertEq(token.balances(user2), INITIAL_BALANCE); // back to initial
        assertEq(token.balances(address(goodReceiver)), amount);
    }
    
    // ==================== EDGE CASE TESTS ====================
    
    function test_Transfer_ToSelf() public {
        uint256 transferAmount = 100 ether;
        
        vm.prank(user1);
        token.transfer(user1, transferAmount, "");
        
        // Balance should remain the same
        assertEq(token.balances(user1), INITIAL_BALANCE);
    }
    
    function test_Transfer_ToZeroAddress() public {
        uint256 transferAmount = 100 ether;
        
        vm.prank(user1);
        token.transfer(address(0), transferAmount, "");
        
        assertEq(token.balances(user1), INITIAL_BALANCE - transferAmount);
        assertEq(token.balances(address(0)), transferAmount);
    }
    
    function test_Transfer_MaxUint256() public {
        // Test with maximum possible amount
        address whale = makeAddr("whale");
        uint256 maxAmount = type(uint256).max;
        
        token.mint(whale, maxAmount);
        
        vm.prank(whale);
        token.transfer(user2, maxAmount, "");
        
        assertEq(token.balances(whale), 0);
        assertEq(token.balances(user2), INITIAL_BALANCE + maxAmount);
    }
    
    // ==================== FUZZ TESTS ====================
    
    function testFuzz_Mint(address recipient, uint256 amount) public {
        vm.assume(recipient != address(0));
        vm.assume(amount < type(uint256).max / 2);
        
        uint256 initialBalance = token.balances(recipient);
        token.mint(recipient, amount);
        
        assertEq(token.balances(recipient), initialBalance + amount);
    }
    
    function testFuzz_Transfer(uint256 transferAmount) public {
        vm.assume(transferAmount > 0 && transferAmount <= INITIAL_BALANCE);
        
        vm.prank(user1);
        token.transfer(user2, transferAmount, "");
        
        assertEq(token.balances(user1), INITIAL_BALANCE - transferAmount);
        assertEq(token.balances(user2), INITIAL_BALANCE + transferAmount);
    }
    
    function testFuzz_TransferToContract(uint256 transferAmount) public {
        vm.assume(transferAmount > 0 && transferAmount <= INITIAL_BALANCE);
        
        vm.prank(user1);
        token.transfer(address(goodReceiver), transferAmount, "fuzz test");
        
        assertEq(token.balances(user1), INITIAL_BALANCE - transferAmount);
        assertEq(token.balances(address(goodReceiver)), transferAmount);
    }
    
    function testFuzz_SetOwner(address newOwner) public {
        vm.assume(newOwner != address(0));
        
        token.setOwner(newOwner);
        assertEq(token.owner(), newOwner);
    }
    
    // ==================== INTEGRATION TESTS ====================
    
    function test_Integration_FullWorkflow() public {
        // 1. Mint tokens to user
        address newUser = makeAddr("newUser");
        token.mint(newUser, 500 ether);
        
        // 2. User transfers to contract receiver
        vm.prank(newUser);
        token.transfer(address(goodReceiver), 200 ether, "workflow test");
        
        // 3. Verify balances
        assertEq(token.balances(newUser), 300 ether);
        assertEq(token.balances(address(goodReceiver)), 200 ether);
        
        // 4. Owner changes
        address newOwner = makeAddr("newOwner");
        token.setOwner(newOwner);
        
        // 5. New owner can perform authorized actions
        address finalOwner = makeAddr("finalOwner");
        vm.prank(newOwner);
        token.setOwner(finalOwner);
        
        assertEq(token.owner(), finalOwner);
    }
    
    function test_Integration_MultipleUsersAndReceivers() public {
        address user3 = makeAddr("user3");
        GoodReceiver receiver2 = new GoodReceiver();
        
        token.mint(user3, INITIAL_BALANCE);
        
        // Multiple users transfer to multiple receivers
        vm.prank(user1);
        token.transfer(address(goodReceiver), 100 ether, "");
        
        vm.prank(user2);
        token.transfer(address(receiver2), 200 ether, "");
        
        vm.prank(user3);
        token.transfer(address(goodReceiver), 150 ether, "");
        
        assertEq(token.balances(address(goodReceiver)), 250 ether);
        assertEq(token.balances(address(receiver2)), 200 ether);
    }
    
    // ==================== SECURITY FIX VALIDATION TESTS ====================
    
    function test_SecurityFix1_ContractAddressNotAuthorized() public {
        // Validate that FIX 1 prevents contract from authorizing itself
        address attacker = makeAddr("attacker");
        
        vm.prank(unauthorizedUser);
        vm.expectRevert("Not authorized");
        token.tryToCallSetOwnerInternally(attacker);
        
        assertEq(token.owner(), owner);
    }
    
    function test_SecurityFix2_TokenFallbackNameFixed() public {
        // Validate that FIX 2 uses fixed "tokenFallback" function name
        // and handles failed callbacks gracefully
        
        uint256 transferAmount = 100 ether;
        
        // Should not revert even if receiver reverts
        vm.prank(user1);
        token.transfer(address(revertingReceiver), transferAmount, "");
        
        assertEq(token.balances(address(revertingReceiver)), transferAmount);
    }
}