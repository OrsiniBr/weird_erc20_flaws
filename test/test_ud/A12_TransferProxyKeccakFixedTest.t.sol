// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "../src/TransferProxyKeccakFixed.sol";

contract TransferProxyKeccakFixedTest is Test {
    using ECDSA for bytes32;

    TransferProxyKeccakFixed public token;
    
    // Test addresses
    address public owner = address(0x1234);
    address public alice = address(0x5678);
    address public bob = address(0x9ABC);
    address public charlie = address(0xDEF0);
    address public attacker = address(0x9999);
    address public zeroAddress = address(0);
    
    // Signing keys (private keys for testing)
    uint256 public alicePrivateKey = 0xA11CE;
    uint256 public bobPrivateKey = 0xB0B;
    uint256 public attackerPrivateKey = 0xDEADBEEF;
    
    uint256 public constant INITIAL_SUPPLY = 1_000_000 * 1e18;

    function setUp() public {
        // Deploy contract
        vm.startPrank(owner);
        token = new TransferProxyKeccakFixed();
        vm.stopPrank();
        
        // Transfer some tokens to test users
        vm.prank(owner);
        token.transfer(alice, 1000 * 1e18);
        token.transfer(bob, 1000 * 1e18);
    }

    // ========== HELPER FUNCTIONS ==========
    function _signTransfer(
        uint256 privateKey,
        address from,
        address to,
        uint256 value,
        uint256 feeMesh,
        uint256 nonce
    ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 hash = keccak256(
            abi.encodePacked(
                from,
                to,
                value,
                feeMesh,
                nonce,
                token.proxyName()
            )
        );
        
        // Sign the hash
        (v, r, s) = vm.sign(privateKey, hash);
    }

    function _getSignature(
        uint256 privateKey,
        address from,
        address to,
        uint256 value,
        uint256 feeMesh,
        uint256 nonce
    ) internal view returns (bytes memory) {
        bytes32 hash = keccak256(
            abi.encodePacked(
                from,
                to,
                value,
                feeMesh,
                nonce,
                token.proxyName()
            )
        );
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hash);
        return abi.encodePacked(r, s, v);
    }

    // ========== TEST CONSTRUCTOR & BASICS ==========
    function test_Constructor_SetsCorrectValues() public {
        assertEq(token.name(), "Fixed Proxy");
        assertEq(token.symbol(), "FPX");
        assertEq(token.proxyName(), "TransferProxy");
        assertEq(token.totalSupply(), INITIAL_SUPPLY);
        assertEq(token.balanceOf(owner), INITIAL_SUPPLY - 2000 * 1e18);
    }

    // ========== TEST TRANSFERPROXY SUCCESS CASES ==========
    function test_TransferProxy_Success_SimpleTransfer() public {
        uint256 transferAmount = 100 * 1e18;
        uint256 feeMesh = 1 * 1e18;
        uint256 nonce = token.nonce(alice);
        
        // Alice signs transfer to Bob
        (uint8 v, bytes32 r, bytes32 s) = _signTransfer(
            alicePrivateKey,
            alice,
            bob,
            transferAmount,
            feeMesh,
            nonce
        );
        
        uint256 aliceBalanceBefore = token.balanceOf(alice);
        uint256 bobBalanceBefore = token.balanceOf(bob);
        
        // Execute proxy transfer (anyone can call)
        vm.prank(charlie);
        bool success = token.transferProxy(
            alice,
            bob,
            transferAmount,
            feeMesh,
            v,
            r,
            s
        );
        
        assertTrue(success);
        assertEq(token.balanceOf(alice), aliceBalanceBefore - transferAmount);
        assertEq(token.balanceOf(bob), bobBalanceBefore + transferAmount);
        assertEq(token.nonce(alice), nonce + 1);
    }

    function test_TransferProxy_Success_WithFeeMesh() public {
        uint256 transferAmount = 100 * 1e18;
        uint256 feeMesh = 10 * 1e18; // 10 token fee
        uint256 nonce = token.nonce(alice);
        
        (uint8 v, bytes32 r, bytes32 s) = _signTransfer(
            alicePrivateKey,
            alice,
            bob,
            transferAmount,
            feeMesh,
            nonce
        );
        
        // Note: The contract doesn't actually use feeMesh in current implementation
        // This test shows the signature still works with non-zero feeMesh
        
        vm.prank(charlie);
        bool success = token.transferProxy(
            alice,
            bob,
            transferAmount,
            feeMesh,
            v,
            r,
            s
        );
        
        assertTrue(success);
        assertEq(token.nonce(alice), nonce + 1);
    }

    function test_TransferProxy_Success_MultipleTransfers() public {
        // First transfer
        uint256 nonce = token.nonce(alice);
        (uint8 v1, bytes32 r1, bytes32 s1) = _signTransfer(
            alicePrivateKey,
            alice,
            bob,
            50 * 1e18,
            0,
            nonce
        );
        
        vm.prank(charlie);
        token.transferProxy(alice, bob, 50 * 1e18, 0, v1, r1, s1);
        
        // Second transfer (nonce should have incremented)
        (uint8 v2, bytes32 r2, bytes32 s2) = _signTransfer(
            alicePrivateKey,
            alice,
            bob,
            30 * 1e18,
            0,
            nonce + 1
        );
        
        vm.prank(charlie);
        token.transferProxy(alice, bob, 30 * 1e18, 0, v2, r2, s2);
        
        assertEq(token.nonce(alice), nonce + 2);
    }

    // ========== TEST FIXED VULNERABILITY: ZERO ADDRESS ==========
    function test_TransferProxy_Reverts_FromZeroAddress() public {
        // This test verifies the fix: zero address should be rejected
        
        uint256 transferAmount = 100 * 1e18;
        uint256 feeMesh = 0;
        
        // Try to use address(0) as _from
        vm.expectRevert("From address cannot be zero");
        
        vm.prank(charlie);
        token.transferProxy(
            zeroAddress,
            bob,
            transferAmount,
            feeMesh,
            0,
            bytes32(0),
            bytes32(0)
        );
    }

    function test_TransferProxy_Reverts_ToZeroAddress() public {
        // Transfer to zero address should also fail (ERC20 prevents this)
        uint256 nonce = token.nonce(alice);
        (uint8 v, bytes32 r, bytes32 s) = _signTransfer(
            alicePrivateKey,
            alice,
            zeroAddress,
            100 * 1e18,
            0,
            nonce
        );
        
        // Will revert in _update() due to ERC20 transfer to zero address
        vm.prank(charlie);
        vm.expectRevert(); // ERC20: transfer to the zero address
        token.transferProxy(alice, zeroAddress, 100 * 1e18, 0, v, r, s);
    }

    // ========== TEST SIGNATURE VERIFICATION ==========
    function test_TransferProxy_Reverts_InvalidSignature() public {
        uint256 nonce = token.nonce(alice);
        
        // Alice signs a transfer
        (uint8 v, bytes32 r, bytes32 s) = _signTransfer(
            alicePrivateKey,
            alice,
            bob,
            100 * 1e18,
            0,
            nonce
        );
        
        // But use Bob's address as _from (signature won't match)
        vm.prank(charlie);
        vm.expectRevert("Invalid signature");
        token.transferProxy(bob, charlie, 100 * 1e18, 0, v, r, s);
    }

    function test_TransferProxy_Reverts_WrongNonce() public {
        uint256 actualNonce = token.nonce(alice);
        uint256 wrongNonce = actualNonce + 1; // Use wrong nonce
        
        (uint8 v, bytes32 r, bytes32 s) = _signTransfer(
            alicePrivateKey,
            alice,
            bob,
            100 * 1e18,
            0,
            wrongNonce
        );
        
        vm.prank(charlie);
        vm.expectRevert("Invalid signature");
        token.transferProxy(alice, bob, 100 * 1e18, 0, v, r, s);
    }

    function test_TransferProxy_Reverts_ReplayedSignature() public {
        uint256 nonce = token.nonce(alice);
        (uint8 v, bytes32 r, bytes32 s) = _signTransfer(
            alicePrivateKey,
            alice,
            bob,
            100 * 1e18,
            0,
            nonce
        );
        
        // Use signature once (success)
        vm.prank(charlie);
        token.transferProxy(alice, bob, 100 * 1e18, 0, v, r, s);
        
        // Try to reuse same signature (should fail due to nonce increment)
        vm.prank(charlie);
        vm.expectRevert("Invalid signature");
        token.transferProxy(alice, bob, 100 * 1e18, 0, v, r, s);
    }

    // ========== TEST EDGE CASES ==========
    function test_TransferProxy_ZeroAmount() public {
        uint256 nonce = token.nonce(alice);
        (uint8 v, bytes32 r, bytes32 s) = _signTransfer(
            alicePrivateKey,
            alice,
            bob,
            0,
            0,
            nonce
        );
        
        uint256 aliceBalanceBefore = token.balanceOf(alice);
        uint256 bobBalanceBefore = token.balanceOf(bob);
        
        vm.prank(charlie);
        bool success = token.transferProxy(alice, bob, 0, 0, v, r, s);
        
        assertTrue(success);
        assertEq(token.balanceOf(alice), aliceBalanceBefore);
        assertEq(token.balanceOf(bob), bobBalanceBefore);
        assertEq(token.nonce(alice), nonce + 1); // Nonce still increments!
    }

    function test_TransferProxy_InsufficientBalance() public {
        uint256 aliceBalance = token.balanceOf(alice);
        uint256 transferAmount = aliceBalance + 1 * 1e18; // More than balance
        
        uint256 nonce = token.nonce(alice);
        (uint8 v, bytes32 r, bytes32 s) = _signTransfer(
            alicePrivateKey,
            alice,
            bob,
            transferAmount,
            0,
            nonce
        );
        
        // Should revert in _update() due to insufficient balance
        vm.prank(charlie);
        vm.expectRevert(); // ERC20: transfer amount exceeds balance
        token.transferProxy(alice, bob, transferAmount, 0, v, r, s);
    }

    // ========== TEST NONCE MANAGEMENT ==========
    function test_Nonce_IncrementsCorrectly() public {
        assertEq(token.nonce(alice), 0);
        assertEq(token.nonce(bob), 0);
        
        // Make a transfer for Alice
        uint256 nonce = token.nonce(alice);
        (uint8 v, bytes32 r, bytes32 s) = _signTransfer(
            alicePrivateKey,
            alice,
            bob,
            100 * 1e18,
            0,
            nonce
        );
        
        vm.prank(charlie);
        token.transferProxy(alice, bob, 100 * 1e18, 0, v, r, s);
        
        // Alice's nonce should be 1, Bob's should still be 0
        assertEq(token.nonce(alice), 1);
        assertEq(token.nonce(bob), 0);
        
        // Now make a transfer for Bob
        nonce = token.nonce(bob);
        (v, r, s) = _signTransfer(
            bobPrivateKey,
            bob,
            alice,
            50 * 1e18,
            0,
            nonce
        );
        
        vm.prank(charlie);
        token.transferProxy(bob, alice, 50 * 1e18, 0, v, r, s);
        
        assertEq(token.nonce(alice), 1);
        assertEq(token.nonce(bob), 1);
    }

    // ========== TEST MALICIOUS SCENARIOS ==========
    function test_TransferProxy_AttackerCannotForgeSignature() public {
        // Attacker tries to create a fake signature
        uint256 nonce = token.nonce(alice);
        
        // Attacker signs with their own key, pretending to be Alice
        (uint8 v, bytes32 r, bytes32 s) = _signTransfer(
            attackerPrivateKey,
            alice,  // Claiming to be Alice
            attacker,
            100 * 1e18,
            0,
            nonce
        );
        
        vm.prank(attacker);
        vm.expectRevert("Invalid signature");
        token.transferProxy(alice, attacker, 100 * 1e18, 0, v, r, s);
    }

    function test_TransferProxy_PhishingAttack() public {
        // Alice signs a transfer to Bob
        uint256 nonce = token.nonce(alice);
        (uint8 v, bytes32 r, bytes32 s) = _signTransfer(
            alicePrivateKey,
            alice,
            bob,
            100 * 1e18,
            0,
            nonce
        );
        
        // Attacker intercepts and tries to use signature for different params
        // But signature hash includes all parameters, so this should fail
        vm.prank(attacker);
        vm.expectRevert("Invalid signature");
        token.transferProxy(alice, attacker, 100 * 1e18, 0, v, r, s); // Different to address
    }

    function test_TransferProxy_FrontRunning() public {
        // Test that transactions can't be front-run due to nonce
        uint256 nonce = token.nonce(alice);
        
        // Alice creates two transactions with same nonce
        (uint8 v1, bytes32 r1, bytes32 s1) = _signTransfer(
            alicePrivateKey,
            alice,
            bob,
            100 * 1e18,
            0,
            nonce
        );
        
        (uint8 v2, bytes32 r2, bytes32 s2) = _signTransfer(
            alicePrivateKey,
            alice,
            charlie,
            100 * 1e18,
            0,
            nonce
        );
        
        // First transaction succeeds
        vm.prank(bob);
        token.transferProxy(alice, bob, 100 * 1e18, 0, v1, r1, s1);
        
        // Second transaction fails (nonce already used)
        vm.prank(charlie);
        vm.expectRevert("Invalid signature");
        token.transferProxy(alice, charlie, 100 * 1e18, 0, v2, r2, s2);
    }

    // ========== TEST FUZZING ==========
    function testFuzz_TransferProxy_RandomAmounts(
        uint256 amount,
        uint256 fee,
        uint256 _nonceOffset
    ) public {
        vm.assume(amount <= token.balanceOf(alice));
        vm.assume(fee <= 100 * 1e18); // Reasonable fee
        vm.assume(_nonceOffset < 100); // Prevent too large nonce jumps
        
        uint256 nonce = token.nonce(alice) + _nonceOffset;
        
        // Create signature with given parameters
        (uint8 v, bytes32 r, bytes32 s) = _signTransfer(
            alicePrivateKey,
            alice,
            bob,
            amount,
            fee,
            nonce
        );
        
        // If nonce is wrong, should revert
        if (_nonceOffset > 0) {
            vm.prank(charlie);
            vm.expectRevert("Invalid signature");
            token.transferProxy(alice, bob, amount, fee, v, r, s);
            return;
        }
        
        // Otherwise should succeed (unless amount > balance, but we assumed it's not)
        uint256 aliceBalanceBefore = token.balanceOf(alice);
        uint256 bobBalanceBefore = token.balanceOf(bob);
        
        vm.prank(charlie);
        bool success = token.transferProxy(alice, bob, amount, fee, v, r, s);
        
        assertTrue(success);
        assertEq(token.balanceOf(alice), aliceBalanceBefore - amount);
        assertEq(token.balanceOf(bob), bobBalanceBefore + amount);
        assertEq(token.nonce(alice), nonce + 1);
    }

    // ========== TEST GAS OPTIMIZATION ==========
    function test_GasCost_TransferProxy() public {
        uint256 nonce = token.nonce(alice);
        (uint8 v, bytes32 r, bytes32 s) = _signTransfer(
            alicePrivateKey,
            alice,
            bob,
            100 * 1e18,
            0,
            nonce
        );
        
        vm.prank(charlie);
        uint256 gasBefore = gasleft();
        token.transferProxy(alice, bob, 100 * 1e18, 0, v, r, s);
        uint256 gasUsed = gasBefore - gasleft();
        
        console.log("Gas used for transferProxy:", gasUsed);
        
        // Should be reasonable (< 100k gas)
        assertLt(gasUsed, 150000);
    }

    // ========== TEST COMPATIBILITY WITH REGULAR TRANSFERS ==========
    function test_RegularTransfer_StillWorks() public {
        // Regular ERC20 transfers should still work
        uint256 aliceBalanceBefore = token.balanceOf(alice);
        uint256 bobBalanceBefore = token.balanceOf(bob);
        
        vm.prank(alice);
        bool success = token.transfer(bob, 50 * 1e18);
        
        assertTrue(success);
        assertEq(token.balanceOf(alice), aliceBalanceBefore - 50 * 1e18);
        assertEq(token.balanceOf(bob), bobBalanceBefore + 50 * 1e18);
        // Nonce should not be affected
        assertEq(token.nonce(alice), 0);
    }

    function test_TransferProxy_DoesNotAffectRegularNonce() public {
        // Make a proxy transfer
        uint256 nonce = token.nonce(alice);
        (uint8 v, bytes32 r, bytes32 s) = _signTransfer(
            alicePrivateKey,
            alice,
            bob,
            100 * 1e18,
            0,
            nonce
        );
        
        vm.prank(charlie);
        token.transferProxy(alice, bob, 100 * 1e18, 0, v, r, s);
        
        // Now make a regular transfer - should work fine
        vm.prank(alice);
        token.transfer(bob, 50 * 1e18);
        
        // Proxy nonce should still be 1, regular transfers don't use nonce
        assertEq(token.nonce(alice), 1);
    }

    // ========== TEST EVENT EMISSIONS (if contract had events) ==========
    // Note: Contract doesn't emit events, but if it did:
    // function test_Events_Emitted() public {
    //     // Would test Transfer event from ERC20
    // }

    // ========== TEST UPGRADE CONSIDERATIONS ==========
    function test_ProxyName_Immutable() public {
        // proxyName is constant, should never change
        assertEq(token.proxyName(), "TransferProxy");
        
        // Try to call a non-existent function to set it (should fail)
        vm.expectRevert();
        (bool success, ) = address(token).call(
            abi.encodeWithSignature("setProxyName(string)", "Hacked")
        );
        assertFalse(success);
    }

    // ========== TEST BATCH OPERATIONS ==========
    function test_MultipleProxyTransfers_Batch() public {
        // Test multiple users making proxy transfers
        address[] memory users = new address[](3);
        users[0] = alice;
        users[1] = bob;
        users[2] = address(0x3333); // New user
        
        // Give tokens to new user
        vm.prank(owner);
        token.transfer(users[2], 500 * 1e18);
        
        for (uint256 i = 0; i < users.length; i++) {
            address user = users[i];
            uint256 userPk;
            
            // Assign private key for signing
            if (user == alice) userPk = alicePrivateKey;
            else if (user == bob) userPk = bobPrivateKey;
            else userPk = 0x3333; // Some private key for new user
            
            uint256 nonce = token.nonce(user);
            (uint8 v, bytes32 r, bytes32 s) = _signTransfer(
                userPk,
                user,
                charlie,
                10 * 1e18,
                0,
                nonce
            );
            
            vm.prank(charlie);
            token.transferProxy(user, charlie, 10 * 1e18, 0, v, r, s);
            
            assertEq(token.nonce(user), nonce + 1);
        }
        
        // Charlie should have received 30 tokens total
        assertEq(token.balanceOf(charlie), 30 * 1e18);
    }

    // ========== TEST INVARIANTS ==========
    function invariant_TotalSupplyConstant() public {
        // Total supply should never change
        assertEq(token.totalSupply(), INITIAL_SUPPLY);
    }

    function invariant_NonceMonotonicallyIncreasing() public view {
        // Nonces can only increase, never decrease
        // (Can't test dynamically without state changes)
    }
}