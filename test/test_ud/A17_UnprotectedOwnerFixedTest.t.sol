// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/UnprotectedOwnerFixed.sol";

contract UnprotectedOwnerFixedTest is Test {
    UnprotectedOwnerFixed public ownerContract;
    
    address public deployer;
    address public user1;
    address public user2;
    address public attacker;
    
    event OwnerSet(address indexed newOwner);
    
    function setUp() public {
        // Setup test accounts
        deployer = address(this);
        user1 = makeAddr("user1");
        user2 = makeAddr("user2");
        attacker = makeAddr("attacker");
        
        // Deploy contract (deployer becomes owner)
        ownerContract = new UnprotectedOwnerFixed();
    }
    
    // ==================== CONSTRUCTOR TESTS ====================
    
    function test_Constructor_SetsDeployerAsOwner() public view {
        assertEq(ownerContract.owner(), deployer);
    }
    
    function test_Constructor_OwnerIsNotZeroAddress() public view {
        assertTrue(ownerContract.owner() != address(0));
    }
    
    // ==================== SET OWNER TESTS - SUCCESS CASES ====================
    
    function test_SetOwner_SuccessAsOwner() public {
        address newOwner = user1;
        
        vm.expectEmit(true, false, false, false);
        emit OwnerSet(newOwner);
        
        ownerContract.setOwner(newOwner);
        
        assertEq(ownerContract.owner(), newOwner);
    }
    
    function test_SetOwner_UpdatesOwnerCorrectly() public {
        ownerContract.setOwner(user1);
        assertEq(ownerContract.owner(), user1);
        
        vm.prank(user1);
        ownerContract.setOwner(user2);
        assertEq(ownerContract.owner(), user2);
    }
    
    function test_SetOwner_EmitsEvent() public {
        address newOwner = user1;
        
        vm.expectEmit(true, false, false, false);
        emit OwnerSet(newOwner);
        
        ownerContract.setOwner(newOwner);
    }
    
    function test_SetOwner_CanSetToZeroAddress() public {
        // Owner can set to zero address (renouncing ownership)
        ownerContract.setOwner(address(0));
        assertEq(ownerContract.owner(), address(0));
    }
    
    function test_SetOwner_CanSetToSameAddress() public {
        // Owner can set owner to themselves
        ownerContract.setOwner(deployer);
        assertEq(ownerContract.owner(), deployer);
    }
    
    function test_SetOwner_MultipleTransfers() public {
        // Transfer 1: deployer -> user1
        ownerContract.setOwner(user1);
        assertEq(ownerContract.owner(), user1);
        
        // Transfer 2: user1 -> user2
        vm.prank(user1);
        ownerContract.setOwner(user2);
        assertEq(ownerContract.owner(), user2);
        
        // Transfer 3: user2 -> deployer
        vm.prank(user2);
        ownerContract.setOwner(deployer);
        assertEq(ownerContract.owner(), deployer);
    }
    
    // ==================== SET OWNER TESTS - SECURITY (FAILURE CASES) ====================
    
    function test_SetOwner_RevertsWhenCalledByNonOwner() public {
        vm.prank(attacker);
        vm.expectRevert("Caller is not the owner");
        ownerContract.setOwner(attacker);
    }
    
    function test_SetOwner_RevertsForAnyNonOwnerAddress() public {
        address[] memory nonOwners = new address[](3);
        nonOwners[0] = user1;
        nonOwners[1] = user2;
        nonOwners[2] = attacker;
        
        for (uint i = 0; i < nonOwners.length; i++) {
            vm.prank(nonOwners[i]);
            vm.expectRevert("Caller is not the owner");
            ownerContract.setOwner(nonOwners[i]);
        }
        
        // Owner should remain unchanged
        assertEq(ownerContract.owner(), deployer);
    }
    
    function test_SetOwner_AttackerCannotTakeOwnership() public {
        // Attacker tries to set themselves as owner
        vm.prank(attacker);
        vm.expectRevert("Caller is not the owner");
        ownerContract.setOwner(attacker);
        
        // Owner should remain deployer
        assertEq(ownerContract.owner(), deployer);
    }
    
    function test_SetOwner_PreviousOwnerCannotReclaim() public {
        // Transfer ownership to user1
        ownerContract.setOwner(user1);
        
        // Deployer (previous owner) cannot reclaim ownership
        vm.expectRevert("Caller is not the owner");
        ownerContract.setOwner(deployer);
        
        assertEq(ownerContract.owner(), user1);
    }
    
    function test_SetOwner_CannotBeCalledByContract() public {
        // Deploy a contract that tries to call setOwner
        MaliciousContract malicious = new MaliciousContract(address(ownerContract));
        
        vm.expectRevert("Caller is not the owner");
        malicious.attemptTakeOwnership(attacker);
    }
    
    // ==================== ONLY OWNER MODIFIER TESTS ====================
    
    function test_OnlyOwner_ChecksMsgSender() public {
        // Only the current owner can call
        ownerContract.setOwner(user1);
        
        // user1 is now owner
        vm.prank(user1);
        ownerContract.setOwner(user2);
        assertEq(ownerContract.owner(), user2);
        
        // user1 is no longer owner
        vm.prank(user1);
        vm.expectRevert("Caller is not the owner");
        ownerContract.setOwner(user1);
    }
    
    function test_OnlyOwner_RevertMessage() public {
        vm.prank(attacker);
        
        // Check exact revert message
        vm.expectRevert("Caller is not the owner");
        ownerContract.setOwner(attacker);
    }
    
    // ==================== EDGE CASE TESTS ====================
    
    function test_EdgeCase_TransferToZeroAndRecover() public {
        // Transfer to zero address (renounce ownership)
        ownerContract.setOwner(address(0));
        assertEq(ownerContract.owner(), address(0));
        
        // Now nobody can set owner (contract is locked)
        vm.prank(deployer);
        vm.expectRevert("Caller is not the owner");
        ownerContract.setOwner(deployer);
        
        vm.prank(user1);
        vm.expectRevert("Caller is not the owner");
        ownerContract.setOwner(user1);
    }
    
    function test_EdgeCase_OwnerCannotTransferIfNotOwner() public {
        // Transfer ownership
        ownerContract.setOwner(user1);
        
        // Original deployer no longer has rights
        vm.expectRevert("Caller is not the owner");
        ownerContract.setOwner(user2);
    }
    
    function test_EdgeCase_ConsecutiveSetOwnerCalls() public {
        // Multiple calls in sequence by same owner
        ownerContract.setOwner(user1);
        
        vm.startPrank(user1);
        ownerContract.setOwner(user2);
        vm.stopPrank();
        
        vm.prank(user2);
        ownerContract.setOwner(deployer);
        
        assertEq(ownerContract.owner(), deployer);
    }
    
    function test_EdgeCase_SetOwnerToContractAddress() public {
        // Owner can set to a contract address
        address contractAddress = address(new DummyContract());
        
        ownerContract.setOwner(contractAddress);
        assertEq(ownerContract.owner(), contractAddress);
    }
    
    // ==================== OWNERSHIP CHAIN TESTS ====================
    
    function test_OwnershipChain_LongChain() public {
        address[] memory owners = new address[](5);
        owners[0] = deployer;
        owners[1] = user1;
        owners[2] = user2;
        owners[3] = makeAddr("user3");
        owners[4] = makeAddr("user4");
        
        // Transfer through chain
        for (uint i = 0; i < owners.length - 1; i++) {
            vm.prank(owners[i]);
            ownerContract.setOwner(owners[i + 1]);
            assertEq(ownerContract.owner(), owners[i + 1]);
        }
        
        // Final owner is user4
        assertEq(ownerContract.owner(), owners[4]);
        
        // Previous owners cannot reclaim
        for (uint i = 0; i < owners.length - 1; i++) {
            vm.prank(owners[i]);
            vm.expectRevert("Caller is not the owner");
            ownerContract.setOwner(owners[i]);
        }
    }
    
    function test_OwnershipChain_CircularTransfer() public {
        // deployer -> user1 -> user2 -> deployer
        ownerContract.setOwner(user1);
        
        vm.prank(user1);
        ownerContract.setOwner(user2);
        
        vm.prank(user2);
        ownerContract.setOwner(deployer);
        
        assertEq(ownerContract.owner(), deployer);
    }
    
    // ==================== MULTIPLE CONTRACT INSTANCES ====================
    
    function test_MultipleInstances_IndependentOwnership() public {
        UnprotectedOwnerFixed contract1 = new UnprotectedOwnerFixed();
        UnprotectedOwnerFixed contract2 = new UnprotectedOwnerFixed();
        
        assertEq(contract1.owner(), deployer);
        assertEq(contract2.owner(), deployer);
        
        // Transfer ownership independently
        contract1.setOwner(user1);
        contract2.setOwner(user2);
        
        assertEq(contract1.owner(), user1);
        assertEq(contract2.owner(), user2);
    }
    
    // ==================== FUZZ TESTS ====================
    
    function testFuzz_SetOwner_ValidOwner(address newOwner) public {
        vm.assume(newOwner != address(0));
        
        ownerContract.setOwner(newOwner);
        assertEq(ownerContract.owner(), newOwner);
    }
    
    function testFuzz_SetOwner_RevertsForNonOwner(address caller, address newOwner) public {
        vm.assume(caller != deployer);
        vm.assume(caller != address(0));
        
        vm.prank(caller);
        vm.expectRevert("Caller is not the owner");
        ownerContract.setOwner(newOwner);
        
        assertEq(ownerContract.owner(), deployer);
    }
    
    function testFuzz_SetOwner_ChainTransfer(address owner1, address owner2, address owner3) public {
        vm.assume(owner1 != address(0) && owner2 != address(0) && owner3 != address(0));
        vm.assume(owner1 != owner2 && owner2 != owner3);
        
        ownerContract.setOwner(owner1);
        
        vm.prank(owner1);
        ownerContract.setOwner(owner2);
        
        vm.prank(owner2);
        ownerContract.setOwner(owner3);
        
        assertEq(ownerContract.owner(), owner3);
    }
    
    // ==================== GAS TESTS ====================
    
    function test_Gas_SetOwner() public {
        uint256 gasBefore = gasleft();
        ownerContract.setOwner(user1);
        uint256 gasUsed = gasBefore - gasleft();
        
        emit log_named_uint("Gas used for setOwner", gasUsed);
    }
    
    function test_Gas_SetOwnerMultipleTimes() public {
        uint256 totalGas = 0;
        
        for (uint i = 0; i < 5; i++) {
            address newOwner = makeAddr(string(abi.encodePacked("owner", i)));
            
            uint256 gasBefore = gasleft();
            
            if (i == 0) {
                ownerContract.setOwner(newOwner);
            } else {
                vm.prank(makeAddr(string(abi.encodePacked("owner", i - 1))));
                ownerContract.setOwner(newOwner);
            }
            
            totalGas += gasBefore - gasleft();
        }
        
        emit log_named_uint("Total gas for 5 transfers", totalGas);
        emit log_named_uint("Average gas per transfer", totalGas / 5);
    }
    
    // ==================== SECURITY COMPARISON TEST ====================
    
    function test_SecurityFix_Comparison() public {
        // This test documents the security improvement
        
        // OLD VULNERABLE VERSION:
        // - No onlyOwner modifier
        // - Anyone could call setOwner
        // - Attacker could steal ownership
        
        // NEW FIXED VERSION:
        // - Has onlyOwner modifier
        // - Only current owner can transfer ownership
        // - Protected against unauthorized access
        
        // Demonstrate the fix
        vm.prank(attacker);
        vm.expectRevert("Caller is not the owner");
        ownerContract.setOwner(attacker);
        
        // Owner remains safe
        assertEq(ownerContract.owner(), deployer);
    }
    
    function test_SecurityFix_MultipleAttackAttempts() public {
        address[] memory attackers = new address[](10);
        for (uint i = 0; i < 10; i++) {
            attackers[i] = makeAddr(string(abi.encodePacked("attacker", i)));
        }
        
        // All attack attempts should fail
        for (uint i = 0; i < attackers.length; i++) {
            vm.prank(attackers[i]);
            vm.expectRevert("Caller is not the owner");
            ownerContract.setOwner(attackers[i]);
        }
        
        // Owner remains unchanged
        assertEq(ownerContract.owner(), deployer);
    }
    
    function test_SecurityFix_SimultaneousAttackAttempts() public {
        // Simulate multiple attackers trying at the same time
        vm.prank(attacker);
        vm.expectRevert("Caller is not the owner");
        ownerContract.setOwner(attacker);
        
        vm.prank(user1);
        vm.expectRevert("Caller is not the owner");
        ownerContract.setOwner(user1);
        
        vm.prank(user2);
        vm.expectRevert("Caller is not the owner");
        ownerContract.setOwner(user2);
        
        // Owner unchanged
        assertEq(ownerContract.owner(), deployer);
    }
    
    // ==================== INTEGRATION TESTS ====================
    
    function test_Integration_OwnershipTransferWorkflow() public {
        // Complete workflow test
        
        // 1. Deployer is initial owner
        assertEq(ownerContract.owner(), deployer);
        
        // 2. Attacker tries to steal ownership (fails)
        vm.prank(attacker);
        vm.expectRevert("Caller is not the owner");
        ownerContract.setOwner(attacker);
        
        // 3. Owner transfers to user1
        ownerContract.setOwner(user1);
        assertEq(ownerContract.owner(), user1);
        
        // 4. Old owner cannot reclaim
        vm.expectRevert("Caller is not the owner");
        ownerContract.setOwner(deployer);
        
        // 5. New owner transfers to user2
        vm.prank(user1);
        ownerContract.setOwner(user2);
        assertEq(ownerContract.owner(), user2);
        
        // 6. Final verification
        assertTrue(ownerContract.owner() != deployer);
        assertTrue(ownerContract.owner() != user1);
        assertTrue(ownerContract.owner() == user2);
    }
}

// Helper contract for testing
contract MaliciousContract {
    UnprotectedOwnerFixed public target;
    
    constructor(address _target) {
        target = UnprotectedOwnerFixed(_target);
    }
    
    function attemptTakeOwnership(address newOwner) public {
        target.setOwner(newOwner);
    }
}

// Dummy contract for testing contract address as owner
contract DummyContract {
    // Empty contract
}