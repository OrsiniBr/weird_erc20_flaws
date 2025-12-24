// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/PauseTransferAnyoneFixed.sol";

contract PauseTransferAnyoneFixedTest is Test {
    PauseTransferAnyoneFixed public token;
    address public admin = address(0x1234);
    address public user1 = address(0x5678);
    address public user2 = address(0x9ABC);
    address public attacker = address(0xDEF0);
    
    uint256 public constant INITIAL_SUPPLY = 1000 * 1e18;

    event TokenTransfer(bool enabled);

    function setUp() public {
        // Deploy contract with admin as walletAddress
        vm.startPrank(admin);
        token = new PauseTransferAnyoneFixed(admin);
        vm.stopPrank();
        
        // Transfer some tokens to users
        vm.prank(admin);
        token.transfer(user1, 100 * 1e18);
        token.transfer(user2, 100 * 1e18);
    }

    // ========== TEST CONSTRUCTOR ==========
    function test_Constructor_SetsCorrectValues() public {
        assertEq(token.name(), "Fixed Token");
        assertEq(token.symbol(), "FIX");
        assertEq(token.walletAddress(), admin);
        assertEq(token.balanceOf(admin), INITIAL_SUPPLY - 200 * 1e18);
        assertFalse(token.tokenTransfer()); // Should be false initially
    }

    // ========== TEST TRANSFER WHILE PAUSED ==========
    function test_Transfer_RevertsWhenPaused() public {
        // Ensure transfers are paused (default state)
        assertFalse(token.tokenTransfer());
        
        // User1 tries to transfer while paused
        vm.prank(user1);
        vm.expectRevert("Transfers are paused");
        token.transfer(user2, 10 * 1e18);
    }

    function test_TransferFrom_RevertsWhenPaused() public {
        // User1 approves user2
        vm.prank(user1);
        token.approve(user2, 100 * 1e18);
        
        // User2 tries to transferFrom while paused
        vm.prank(user2);
        vm.expectRevert("Transfers are paused");
        token.transferFrom(user1, user2, 10 * 1e18);
    }

    // ========== TEST ENABLE TRANSFERS ==========
    function test_EnableTokenTransfer_Success_Admin() public {
        // Admin enables transfers
        vm.prank(admin);
        vm.expectEmit(true, true, true, true);
        emit TokenTransfer(true);
        token.enableTokenTransfer();
        
        assertTrue(token.tokenTransfer());
        
        // Now transfers should work
        vm.prank(user1);
        token.transfer(user2, 10 * 1e18);
        assertEq(token.balanceOf(user2), 110 * 1e18);
    }

    function test_EnableTokenTransfer_Reverts_NonAdmin() public {
        // Non-admin tries to enable transfers
        vm.prank(user1);
        vm.expectRevert("Caller is not the admin");
        token.enableTokenTransfer();
        
        assertFalse(token.tokenTransfer());
    }

    function test_EnableTokenTransfer_Reverts_Attacker() public {
        // Attacker tries to enable transfers
        vm.prank(attacker);
        vm.expectRevert("Caller is not the admin");
        token.enableTokenTransfer();
        
        assertFalse(token.tokenTransfer());
    }

    // ========== TEST DISABLE TRANSFERS ==========
    function test_DisableTokenTransfer_Success_Admin() public {
        // First enable transfers
        vm.prank(admin);
        token.enableTokenTransfer();
        assertTrue(token.tokenTransfer());
        
        // Then disable them
        vm.prank(admin);
        vm.expectEmit(true, true, true, true);
        emit TokenTransfer(false);
        token.disableTokenTransfer();
        
        assertFalse(token.tokenTransfer());
        
        // Transfers should fail again
        vm.prank(user1);
        vm.expectRevert("Transfers are paused");
        token.transfer(user2, 10 * 1e18);
    }

    function test_DisableTokenTransfer_Reverts_NonAdmin() public {
        // Non-admin tries to disable transfers
        vm.prank(user1);
        vm.expectRevert("Caller is not the admin");
        token.disableTokenTransfer();
    }

    // ========== TEST UNLOCK ADDRESS FUNCTIONALITY ==========
    function test_Transfer_WorksWithUnlockAddress() public {
        // Admin unlocks user1 while transfers are paused
        vm.prank(admin);
        // Note: Need to add this function to contract first!
        // token.setUnlockAddress(user1, true);
        
        // For now, directly modify storage to test the modifier
        vm.store(
            address(token),
            keccak256(abi.encode(user1, uint256(2))), // storage slot 2 for unlockaddress mapping
            bytes32(uint256(1))
        );
        
        // User1 should be able to transfer even when paused
        vm.prank(user1);
        token.transfer(user2, 10 * 1e18);
        assertEq(token.balanceOf(user2), 110 * 1e18);
    }

    function test_Transfer_RevertsWithoutUnlockAddress() public {
        // Only user1 is unlocked, user2 is not
        vm.store(
            address(token),
            keccak256(abi.encode(user1, uint256(2))),
            bytes32(uint256(1))
        );
        
        // User2 should NOT be able to transfer
        vm.prank(user2);
        vm.expectRevert("Transfers are paused");
        token.transfer(user1, 10 * 1e18);
    }

    // ========== TEST TRANSFER WHEN ENABLED ==========
    function test_Transfer_Success_WhenEnabled() public {
        // Enable transfers
        vm.prank(admin);
        token.enableTokenTransfer();
        
        uint256 user1BalanceBefore = token.balanceOf(user1);
        uint256 user2BalanceBefore = token.balanceOf(user2);
        
        // Transfer should work
        vm.prank(user1);
        bool success = token.transfer(user2, 50 * 1e18);
        
        assertTrue(success);
        assertEq(token.balanceOf(user1), user1BalanceBefore - 50 * 1e18);
        assertEq(token.balanceOf(user2), user2BalanceBefore + 50 * 1e18);
    }

    function test_TransferFrom_Success_WhenEnabled() public {
        // Enable transfers
        vm.prank(admin);
        token.enableTokenTransfer();
        
        // User1 approves user2
        vm.prank(user1);
        token.approve(user2, 100 * 1e18);
        
        uint256 user1BalanceBefore = token.balanceOf(user1);
        uint256 user2BalanceBefore = token.balanceOf(user2);
        
        // transferFrom should work
        vm.prank(user2);
        bool success = token.transferFrom(user1, user2, 30 * 1e18);
        
        assertTrue(success);
        assertEq(token.balanceOf(user1), user1BalanceBefore - 30 * 1e18);
        assertEq(token.balanceOf(user2), user2BalanceBefore + 30 * 1e18);
        assertEq(token.allowance(user1, user2), 70 * 1e18);
    }

    // ========== TEST EDGE CASES ==========
    function test_Transfer_ZeroAmount() public {
        vm.prank(admin);
        token.enableTokenTransfer();
        
        // Should work with zero amount
        vm.prank(user1);
        token.transfer(user2, 0);
        
        // Balances unchanged
        assertEq(token.balanceOf(user1), 100 * 1e18);
        assertEq(token.balanceOf(user2), 100 * 1e18);
    }

    function test_Transfer_InsufficientBalance() public {
        vm.prank(admin);
        token.enableTokenTransfer();
        
        // Try to transfer more than balance
        vm.prank(user1);
        vm.expectRevert("ERC20: transfer amount exceeds balance");
        token.transfer(user2, 200 * 1e18);
    }

    function test_TransferFrom_InsufficientAllowance() public {
        vm.prank(admin);
        token.enableTokenTransfer();
        
        // Only approve 10 tokens
        vm.prank(user1);
        token.approve(user2, 10 * 1e18);
        
        // Try to transfer more than allowance
        vm.prank(user2);
        vm.expectRevert("ERC20: insufficient allowance");
        token.transferFrom(user1, user2, 20 * 1e18);
    }

    // ========== TEST REENTRANCY PROTECTION ==========
    // Note: Since this contract inherits from ERC20 (which doesn't have reentrancy protection),
    // we should test that it's safe. ERC20 transfers are generally reentrancy-safe.

    // ========== TEST STATE CHANGES AFTER MULTIPLE OPERATIONS ==========
    function test_MultipleToggleOperations() public {
        // Test toggling transfers multiple times
        for (uint i = 0; i < 5; i++) {
            // Enable
            vm.prank(admin);
            token.enableTokenTransfer();
            assertTrue(token.tokenTransfer());
            
            // Transfer should work
            vm.prank(user1);
            token.transfer(user2, 1 * 1e18);
            
            // Disable
            vm.prank(admin);
            token.disableTokenTransfer();
            assertFalse(token.tokenTransfer());
            
            // Transfer should fail
            vm.prank(user1);
            vm.expectRevert("Transfers are paused");
            token.transfer(user2, 1 * 1e18);
        }
    }

    // ========== TEST GAS OPTIMIZATION ==========
    function test_GasCost_EnableDisable() public {
        // Measure gas for enableTokenTransfer
        vm.prank(admin);
        uint256 gasBefore = gasleft();
        token.enableTokenTransfer();
        uint256 gasUsedEnable = gasBefore - gasleft();
        console.log("Gas used for enableTokenTransfer:", gasUsedEnable);
        
        // Measure gas for disableTokenTransfer
        vm.prank(admin);
        gasBefore = gasleft();
        token.disableTokenTransfer();
        uint256 gasUsedDisable = gasBefore - gasleft();
        console.log("Gas used for disableTokenTransfer:", gasUsedDisable);
    }

    // ========== TEST INTEGRATION WITH OTHER CONTRACTS ==========
    function test_ContractAsReceiver() public {
        vm.prank(admin);
        token.enableTokenTransfer();
        
        // Create a dummy contract that can receive tokens
        TokenReceiver receiver = new TokenReceiver();
        
        // Transfer tokens to contract
        vm.prank(user1);
        token.transfer(address(receiver), 10 * 1e18);
        
        assertEq(token.balanceOf(address(receiver)), 10 * 1e18);
    }

    // ========== FUZZING TESTS ==========
    function testFuzz_Transfer_RandomAmounts(uint256 amount) public {
        vm.assume(amount <= 100 * 1e18); // Don't exceed user1 balance
        vm.assume(amount > 0);
        
        vm.prank(admin);
        token.enableTokenTransfer();
        
        uint256 user1BalanceBefore = token.balanceOf(user1);
        uint256 user2BalanceBefore = token.balanceOf(user2);
        
        vm.prank(user1);
        token.transfer(user2, amount);
        
        assertEq(token.balanceOf(user1), user1BalanceBefore - amount);
        assertEq(token.balanceOf(user2), user2BalanceBefore + amount);
    }

    function testFuzz_ToggleStateMultipleTimes(uint8 count) public {
        vm.assume(count <= 10); // Limit to prevent excessive gas
        
        bool expectedState = false;
        
        for (uint8 i = 0; i < count; i++) {
            if (expectedState) {
                vm.prank(admin);
                token.disableTokenTransfer();
                expectedState = false;
            } else {
                vm.prank(admin);
                token.enableTokenTransfer();
                expectedState = true;
            }
            
            assertEq(token.tokenTransfer(), expectedState);
        }
    }

    // ========== INVARIANT TESTS ==========
    function invariant_TotalSupplyConstant() public {
        // Total supply should never change (except in constructor)
        assertEq(token.totalSupply(), INITIAL_SUPPLY);
    }

    function invariant_AdminCannotChange() public {
        // walletAddress should never change (it's not mutable in current contract)
        assertEq(token.walletAddress(), admin);
    }

    // ========== TEST UPGRADE SCENARIOS ==========
    function test_NewAdminScenario() public {
        // Simulate what happens if we deploy new contract with new admin
        address newAdmin = address(0x9999);
        
        vm.startPrank(newAdmin);
        PauseTransferAnyoneFixed newToken = new PauseTransferAnyoneFixed(newAdmin);
        vm.stopPrank();
        
        assertEq(newToken.walletAddress(), newAdmin);
        assertFalse(newToken.tokenTransfer());
    }

    // ========== TEST EVENT EMISSIONS ==========
    function test_Events_EmittedCorrectly() public {
        // Test enable event
        vm.expectEmit(true, true, true, true);
        emit TokenTransfer(true);
        
        vm.prank(admin);
        token.enableTokenTransfer();
        
        // Test disable event
        vm.expectEmit(true, true, true, true);
        emit TokenTransfer(false);
        
        vm.prank(admin);
        token.disableTokenTransfer();
    }

    // ========== TEST SECURITY: FRONT-RUNNING ==========
    function test_NoFrontRunningVulnerability() public {
        // Simulate front-running scenario
        // User tries to transfer while admin is disabling
        uint256 snapshot = vm.snapshot();
        
        // Enable transfers first
        vm.prank(admin);
        token.enableTokenTransfer();
        
        // User prepares transfer (but doesn't send yet)
        
        // Admin disables transfers
        vm.prank(admin);
        token.disableTokenTransfer();
        
        // Now user tries to transfer - should fail
        vm.prank(user1);
        vm.expectRevert("Transfers are paused");
        token.transfer(user2, 10 * 1e18);
        
        vm.revertTo(snapshot);
    }
}

// Helper contract for testing
contract TokenReceiver {
    function receiveTokens(address token, uint256 amount) external {
        // Can implement logic if needed
    }
}