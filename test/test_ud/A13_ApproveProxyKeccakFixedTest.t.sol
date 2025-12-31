// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../src/ApproveProxyKeccakFixed.sol";

contract ApproveProxyKeccakFixedTest is Test {
    ApproveProxyKeccakFixed public token;
    
    // Test accounts
    address public owner;
    uint256 public ownerPrivateKey;
    
    address public spender;
    address public recipient;
    
    // Constants
    uint256 constant INITIAL_BALANCE = 1000 ether;
    uint256 constant APPROVAL_AMOUNT = 100 ether;
    
    function setUp() public {
        // Deploy contract
        token = new ApproveProxyKeccakFixed();
        
        // Setup test accounts
        ownerPrivateKey = 0xA11CE;
        owner = vm.addr(ownerPrivateKey);
        
        spender = makeAddr("spender");
        recipient = makeAddr("recipient");
        
        // Mint initial balance to owner
        token.mint(owner, INITIAL_BALANCE);
    }
    
    // ==================== HELPER FUNCTIONS ====================
    
    function _getApprovalHash(
        address from,
        address _spender,
        uint256 value,
        uint256 nonce
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(from, _spender, value, nonce, token.name())
        );
    }
    
    function _signApproval(
        uint256 privateKey,
        address from,
        address _spender,
        uint256 value,
        uint256 nonce
    ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 hash = _getApprovalHash(from, _spender, value, nonce);
        (v, r, s) = vm.sign(privateKey, hash);
    }
    
    // ==================== MINT TESTS ====================
    
    function test_Mint() public {
        address user = makeAddr("user");
        uint256 amount = 500 ether;
        
        token.mint(user, amount);
        
        assertEq(token.balances(user), amount);
    }
    
    function test_MintMultipleTimes() public {
        address user = makeAddr("user");
        
        token.mint(user, 100 ether);
        token.mint(user, 200 ether);
        
        assertEq(token.balances(user), 300 ether);
    }
    
    // ==================== APPROVE PROXY TESTS ====================
    
    function test_ApproveProxy_Success() public {
        uint256 nonce = token.nonces(owner);
        (uint8 v, bytes32 r, bytes32 s) = _signApproval(
            ownerPrivateKey,
            owner,
            spender,
            APPROVAL_AMOUNT,
            nonce
        );
        
        vm.expectEmit(true, true, false, true);
        emit ApproveProxyKeccakFixed.Approval(owner, spender, APPROVAL_AMOUNT);
        
        bool success = token.approveProxy(owner, spender, APPROVAL_AMOUNT, v, r, s);
        
        assertTrue(success);
        assertEq(token.allowance(owner, spender), APPROVAL_AMOUNT);
        assertEq(token.nonces(owner), nonce + 1);
    }
    
    function test_ApproveProxy_RevertsOnZeroAddress() public {
        address from = address(0);
        uint256 nonce = 0;
        
        (uint8 v, bytes32 r, bytes32 s) = _signApproval(
            ownerPrivateKey,
            from,
            spender,
            APPROVAL_AMOUNT,
            nonce
        );
        
        vm.expectRevert("From address cannot be zero");
        token.approveProxy(from, spender, APPROVAL_AMOUNT, v, r, s);
    }
    
    function test_ApproveProxy_RevertsOnInvalidSignature() public {
        uint256 wrongPrivateKey = 0xBAD;
        uint256 nonce = token.nonces(owner);
        
        (uint8 v, bytes32 r, bytes32 s) = _signApproval(
            wrongPrivateKey,
            owner,
            spender,
            APPROVAL_AMOUNT,
            nonce
        );
        
        vm.expectRevert("Invalid signature");
        token.approveProxy(owner, spender, APPROVAL_AMOUNT, v, r, s);
    }
    
    function test_ApproveProxy_RevertsOnWrongNonce() public {
        uint256 wrongNonce = 999;
        
        (uint8 v, bytes32 r, bytes32 s) = _signApproval(
            ownerPrivateKey,
            owner,
            spender,
            APPROVAL_AMOUNT,
            wrongNonce
        );
        
        vm.expectRevert("Invalid signature");
        token.approveProxy(owner, spender, APPROVAL_AMOUNT, v, r, s);
    }
    
    function test_ApproveProxy_RevertsOnWrongAmount() public {
        uint256 nonce = token.nonces(owner);
        uint256 signedAmount = APPROVAL_AMOUNT;
        uint256 differentAmount = APPROVAL_AMOUNT + 1 ether;
        
        (uint8 v, bytes32 r, bytes32 s) = _signApproval(
            ownerPrivateKey,
            owner,
            spender,
            signedAmount,
            nonce
        );
        
        vm.expectRevert("Invalid signature");
        token.approveProxy(owner, spender, differentAmount, v, r, s);
    }
    
    function test_ApproveProxy_RevertsOnWrongSpender() public {
        uint256 nonce = token.nonces(owner);
        address differentSpender = makeAddr("differentSpender");
        
        (uint8 v, bytes32 r, bytes32 s) = _signApproval(
            ownerPrivateKey,
            owner,
            spender,
            APPROVAL_AMOUNT,
            nonce
        );
        
        vm.expectRevert("Invalid signature");
        token.approveProxy(owner, differentSpender, APPROVAL_AMOUNT, v, r, s);
    }
    
    function test_ApproveProxy_NonceIncrementsCorrectly() public {
        uint256 initialNonce = token.nonces(owner);
        
        // First approval
        (uint8 v1, bytes32 r1, bytes32 s1) = _signApproval(
            ownerPrivateKey,
            owner,
            spender,
            APPROVAL_AMOUNT,
            initialNonce
        );
        token.approveProxy(owner, spender, APPROVAL_AMOUNT, v1, r1, s1);
        assertEq(token.nonces(owner), initialNonce + 1);
        
        // Second approval
        (uint8 v2, bytes32 r2, bytes32 s2) = _signApproval(
            ownerPrivateKey,
            owner,
            spender,
            APPROVAL_AMOUNT * 2,
            initialNonce + 1
        );
        token.approveProxy(owner, spender, APPROVAL_AMOUNT * 2, v2, r2, s2);
        assertEq(token.nonces(owner), initialNonce + 2);
    }
    
    function test_ApproveProxy_CannotReuseSignature() public {
        uint256 nonce = token.nonces(owner);
        
        (uint8 v, bytes32 r, bytes32 s) = _signApproval(
            ownerPrivateKey,
            owner,
            spender,
            APPROVAL_AMOUNT,
            nonce
        );
        
        // First call succeeds
        token.approveProxy(owner, spender, APPROVAL_AMOUNT, v, r, s);
        
        // Second call with same signature fails
        vm.expectRevert("Invalid signature");
        token.approveProxy(owner, spender, APPROVAL_AMOUNT, v, r, s);
    }
    
    function test_ApproveProxy_UpdatesAllowance() public {
        uint256 nonce = token.nonces(owner);
        
        // First approval
        (uint8 v1, bytes32 r1, bytes32 s1) = _signApproval(
            ownerPrivateKey,
            owner,
            spender,
            APPROVAL_AMOUNT,
            nonce
        );
        token.approveProxy(owner, spender, APPROVAL_AMOUNT, v1, r1, s1);
        assertEq(token.allowance(owner, spender), APPROVAL_AMOUNT);
        
        // Second approval overwrites
        (uint8 v2, bytes32 r2, bytes32 s2) = _signApproval(
            ownerPrivateKey,
            owner,
            spender,
            APPROVAL_AMOUNT * 2,
            nonce + 1
        );
        token.approveProxy(owner, spender, APPROVAL_AMOUNT * 2, v2, r2, s2);
        assertEq(token.allowance(owner, spender), APPROVAL_AMOUNT * 2);
    }
    
    // ==================== TRANSFER FROM TESTS ====================
    
    function test_TransferFrom_Success() public {
        // Setup approval
        uint256 nonce = token.nonces(owner);
        (uint8 v, bytes32 r, bytes32 s) = _signApproval(
            ownerPrivateKey,
            owner,
            spender,
            APPROVAL_AMOUNT,
            nonce
        );
        token.approveProxy(owner, spender, APPROVAL_AMOUNT, v, r, s);
        
        // Transfer
        uint256 transferAmount = 50 ether;
        vm.prank(spender);
        token.transferFrom(owner, recipient, transferAmount);
        
        assertEq(token.balances(owner), INITIAL_BALANCE - transferAmount);
        assertEq(token.balances(recipient), transferAmount);
        assertEq(token.allowance(owner, spender), APPROVAL_AMOUNT - transferAmount);
    }
    
    function test_TransferFrom_RevertsOnInsufficientBalance() public {
        address poorOwner = makeAddr("poorOwner");
        token.mint(poorOwner, 10 ether);
        
        // Mock approval (we won't actually set it up properly)
        vm.store(
            address(token),
            keccak256(abi.encode(spender, keccak256(abi.encode(poorOwner, 1)))),
            bytes32(uint256(100 ether))
        );
        
        vm.prank(spender);
        vm.expectRevert("Insufficient balance");
        token.transferFrom(poorOwner, recipient, 50 ether);
    }
    
    function test_TransferFrom_RevertsOnInsufficientAllowance() public {
        // Setup small approval
        uint256 nonce = token.nonces(owner);
        uint256 smallApproval = 10 ether;
        (uint8 v, bytes32 r, bytes32 s) = _signApproval(
            ownerPrivateKey,
            owner,
            spender,
            smallApproval,
            nonce
        );
        token.approveProxy(owner, spender, smallApproval, v, r, s);
        
        // Try to transfer more than approved
        vm.prank(spender);
        vm.expectRevert("Insufficient allowance");
        token.transferFrom(owner, recipient, 50 ether);
    }
    
    function test_TransferFrom_MultipleTransfers() public {
        // Setup approval
        uint256 nonce = token.nonces(owner);
        (uint8 v, bytes32 r, bytes32 s) = _signApproval(
            ownerPrivateKey,
            owner,
            spender,
            APPROVAL_AMOUNT,
            nonce
        );
        token.approveProxy(owner, spender, APPROVAL_AMOUNT, v, r, s);
        
        // First transfer
        vm.prank(spender);
        token.transferFrom(owner, recipient, 30 ether);
        
        // Second transfer
        vm.prank(spender);
        token.transferFrom(owner, recipient, 20 ether);
        
        assertEq(token.balances(recipient), 50 ether);
        assertEq(token.allowance(owner, spender), APPROVAL_AMOUNT - 50 ether);
    }
    
    // ==================== INTEGRATION TESTS ====================
    
    function test_Integration_FullApprovalAndTransferFlow() public {
        // Step 1: Mint tokens to owner
        assertEq(token.balances(owner), INITIAL_BALANCE);
        
        // Step 2: Owner signs approval for spender
        uint256 nonce = token.nonces(owner);
        (uint8 v, bytes32 r, bytes32 s) = _signApproval(
            ownerPrivateKey,
            owner,
            spender,
            APPROVAL_AMOUNT,
            nonce
        );
        
        // Step 3: Anyone can submit the approval transaction
        token.approveProxy(owner, spender, APPROVAL_AMOUNT, v, r, s);
        assertEq(token.allowance(owner, spender), APPROVAL_AMOUNT);
        
        // Step 4: Spender transfers tokens
        vm.prank(spender);
        token.transferFrom(owner, recipient, 50 ether);
        
        // Step 5: Verify final state
        assertEq(token.balances(owner), INITIAL_BALANCE - 50 ether);
        assertEq(token.balances(recipient), 50 ether);
        assertEq(token.allowance(owner, spender), APPROVAL_AMOUNT - 50 ether);
    }
    
    function test_Integration_MultipleUsersApprovals() public {
        // Setup second owner
        uint256 owner2PrivateKey = 0xB0B;
        address owner2 = vm.addr(owner2PrivateKey);
        token.mint(owner2, INITIAL_BALANCE);
        
        // Owner 1 approves spender
        uint256 nonce1 = token.nonces(owner);
        (uint8 v1, bytes32 r1, bytes32 s1) = _signApproval(
            ownerPrivateKey,
            owner,
            spender,
            APPROVAL_AMOUNT,
            nonce1
        );
        token.approveProxy(owner, spender, APPROVAL_AMOUNT, v1, r1, s1);
        
        // Owner 2 approves spender
        uint256 nonce2 = token.nonces(owner2);
        (uint8 v2, bytes32 r2, bytes32 s2) = _signApproval(
            owner2PrivateKey,
            owner2,
            spender,
            APPROVAL_AMOUNT * 2,
            nonce2
        );
        token.approveProxy(owner2, spender, APPROVAL_AMOUNT * 2, v2, r2, s2);
        
        // Verify independent allowances
        assertEq(token.allowance(owner, spender), APPROVAL_AMOUNT);
        assertEq(token.allowance(owner2, spender), APPROVAL_AMOUNT * 2);
    }
    
    // ==================== FUZZ TESTS ====================
    
    function testFuzz_ApproveProxy(uint256 amount) public {
        vm.assume(amount > 0 && amount < type(uint256).max / 2);
        
        uint256 nonce = token.nonces(owner);
        (uint8 v, bytes32 r, bytes32 s) = _signApproval(
            ownerPrivateKey,
            owner,
            spender,
            amount,
            nonce
        );
        
        token.approveProxy(owner, spender, amount, v, r, s);
        assertEq(token.allowance(owner, spender), amount);
    }
    
    function testFuzz_TransferFrom(uint256 mintAmount, uint256 approvalAmount, uint256 transferAmount) public {
        vm.assume(mintAmount > 0 && mintAmount < type(uint256).max / 2);
        vm.assume(approvalAmount > 0 && approvalAmount <= mintAmount);
        vm.assume(transferAmount > 0 && transferAmount <= approvalAmount);
        
        address user = makeAddr("user");
        token.mint(user, mintAmount);
        
        // Mock approval
        vm.store(
            address(token),
            keccak256(abi.encode(spender, keccak256(abi.encode(user, 1)))),
            bytes32(approvalAmount)
        );
        
        vm.prank(spender);
        token.transferFrom(user, recipient, transferAmount);
        
        assertEq(token.balances(user), mintAmount - transferAmount);
        assertEq(token.balances(recipient), transferAmount);
    }
    
    // ==================== CONSTANT TESTS ====================
    
    function test_NameConstant() public view {
        assertEq(token.name(), "ApproveProxy");
    }
}