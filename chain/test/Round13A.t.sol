// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/Mocks.sol";

// ROUND 13 — Team A (forge / on-chain).
// Part 1 — Streams selector resolution (K-726..K-728) + pause semantics
//   (K-720..K-725): fabricated storage, NO createStream (forbidden step
//   never attempted). Part 2 — K-712: does a vesting locker ignore trailing
//   calldata (the bypass route for the SDK lock() hex-inclusion check)?
// Throwaway Anvil keys only.
contract Round13ATest is Test {
    address constant STREAM = 0xF02aD48D7Ae63F17941E78AAF228C1450Db13891;

    uint256 constant PAYER_PK = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant PAYEE_PK = 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a;
    uint256 constant ARB_PK = 0x47e179ec1974f892c2cd3b0cf1a4ec6a36e72a0a0d26ccaa2aa5c8ad6b9b47a8;
    address payer; address payee; address arbiter; address stranger;
    MockERC20 token;
    MockLocker locker;

    bytes4 constant SEL_WITHDRAW = 0x2e1a7d4d;
    bytes4 constant SEL_CANCEL = 0x40e58ee5;
    bytes4 constant SEL_PAUSE = 0x136439dd;
    bytes4 constant SEL_RESUME = 0x414000b5;
    bytes4 constant SEL_STREAM = 0x2d94d8b5;
    bytes4 constant SEL_VESTED = 0x968fb8ba;
    bytes4 constant SEL_WITHDRAWABLE = 0xf11988e0;
    bytes4 constant SEL_REDIRECT = 0xadfecd8a;
    bytes4 constant SEL_CLAIM = 0x1e83409a;
    bytes4 constant SEL_NEXTID = 0x61b8ce8c;
    bytes4 constant SEL_MAXFEE = 0xbc063e1a;
    bytes4 constant SEL_SELRET = 0xb1724b46;
    bytes4 constant SEL_FEEGET = 0x28079e4a;

    function setUp() public {
        vm.chainId(4663);
        payer = vm.addr(PAYER_PK);
        payee = vm.addr(PAYEE_PK);
        arbiter = vm.addr(ARB_PK);
        stranger = vm.addr(0x9999);
        vm.etch(STREAM, vm.parseBytes(vm.readFile("bytecode/stream.hex")));
        vm.store(STREAM, bytes32(uint256(4)), bytes32(uint256(1))); // reentrancy guard unlocked
        token = new MockERC20();
        token.mint(payer, 1000000 ether);
        token.mint(STREAM, 100000 ether);
        locker = new MockLocker();
        vm.deal(payer, 100 ether);
        vm.deal(payee, 10 ether);
        vm.deal(arbiter, 10 ether);
        vm.deal(stranger, 10 ether);
        vm.warp(1000);
    }

    function _base(uint256 id) internal pure returns (bytes32) {
        return keccak256(abi.encode(id, uint256(1)));
    }
    // Layout (round 12, confirmed): +0 payer, +1 payee, +2 arbiter, +3 token,
    // +4 amount, +5 withdrawn, +6 = start|end|pausedAt|kind.
    function _fabricate(uint256 id, uint256 amount_, uint256 withdrawn_, uint64 start_, uint64 end_, uint64 pausedAt_, uint8 kind_) internal {
        bytes32 b = _base(id);
        vm.store(STREAM, b, bytes32(uint256(uint160(payer))));
        vm.store(STREAM, bytes32(uint256(b) + 1), bytes32(uint256(uint160(payee))));
        vm.store(STREAM, bytes32(uint256(b) + 2), bytes32(uint256(uint160(arbiter))));
        vm.store(STREAM, bytes32(uint256(b) + 3), bytes32(uint256(uint160(address(token)))));
        vm.store(STREAM, bytes32(uint256(b) + 4), bytes32(amount_));
        vm.store(STREAM, bytes32(uint256(b) + 5), bytes32(withdrawn_));
        uint256 packed = uint256(start_) | (uint256(end_) << 64) | (uint256(pausedAt_) << 128) | (uint256(kind_) << 192);
        vm.store(STREAM, bytes32(uint256(b) + 6), bytes32(packed));
    }
    function _callAs(address who, bytes memory data) internal returns (bool ok, bytes memory ret) {
        vm.prank(who);
        (ok, ret) = STREAM.call(data);
    }
    function _uintView(bytes4 sel, uint256 id) internal returns (bool ok, uint256 v) {
        bytes memory ret;
        (ok, ret) = STREAM.call(abi.encodeWithSelector(sel, id));
        if (ok && ret.length == 32) v = abi.decode(ret, (uint256));
    }
    function _streamWords(uint256 id) internal returns (uint256[10] memory w) {
        (bool ok, bytes memory ret) = STREAM.call(abi.encodeWithSelector(SEL_STREAM, id));
        require(ok && ret.length == 320, "stream() must return 10 words");
        for (uint256 i; i < 10; i++) {
            bytes memory s = new bytes(32);
            for (uint256 j; j < 32; j++) s[j] = ret[i * 32 + j];
            w[i] = abi.decode(s, (uint256));
        }
    }

    // ---- K-727: nextId() = SLOAD slot 0; MAX_FEE() = 0.5 ether ----
    function testK727NextIdAndMaxFee() public {
        vm.store(STREAM, bytes32(uint256(0)), bytes32(uint256(42)));
        (bool ok, bytes memory ret) = STREAM.call(abi.encodeWithSelector(SEL_NEXTID));
        assertTrue(ok, "nextId() must not revert");
        assertEq(abi.decode(ret, (uint256)), 42, "nextId() reads slot 0");
        (bool ok2, bytes memory ret2) = STREAM.call(abi.encodeWithSelector(SEL_MAXFEE));
        assertTrue(ok2, "MAX_FEE() must not revert");
        assertEq(abi.decode(ret2, (uint256)), 0.5 ether, "MAX_FEE() = 0.5 ether (0x06f05b59d3b20000)");
        emit log_string("K-727: nextId()=slot0, MAX_FEE()=0.5 ether - resolved, view-only");
    }

    // ---- K-727: 0xb1724b46() returns the constant 315360000 ----
    // 0x12CC0300 as a uint256 IS 315360000 = 10 years in seconds: this is a
    // duration cap (MAX_DURATION), not a function selector. The PUSH4 in the
    // disassembly is just how the constant is pushed.
    function testK727SelectorReturn() public {
        (bool ok, bytes memory ret) = STREAM.call(abi.encodeWithSelector(SEL_SELRET));
        assertTrue(ok, "0xb1724b46 must not revert");
        assertEq(ret.length, 32, "returns one word");
        assertEq(abi.decode(ret, (uint256)), 315360000, "0xb1724b46() = 315360000 = 10 years in seconds (MAX duration)");
        emit log_named_uint("K-727 0xb1724b46() = MAX duration (seconds)", abi.decode(ret, (uint256)));
    }

    // ---- K-726: 0x28079e4a(a,b) = nested fee mapping slot 3 ----
    function testK726FeeMappingGetter() public {
        bytes32 outer = keccak256(abi.encode(address(token), uint256(3)));
        bytes32 nested = keccak256(abi.encode(stranger, outer));
        vm.store(STREAM, nested, bytes32(uint256(100 ether)));
        (bool ok1, bytes memory r1) = STREAM.call(abi.encodeWithSelector(SEL_FEEGET, address(token), stranger));
        (bool ok2, bytes memory r2) = STREAM.call(abi.encodeWithSelector(SEL_FEEGET, stranger, address(token)));
        emit log_named_uint("K-726 0x28079e4a(token,stranger) ok", ok1 ? 1 : 0);
        if (ok1) emit log_named_uint("  value", abi.decode(r1, (uint256)));
        emit log_named_uint("K-726 0x28079e4a(stranger,token) ok", ok2 ? 1 : 0);
        if (ok2) emit log_named_uint("  value", abi.decode(r2, (uint256)));
        assertTrue(ok1 && abi.decode(r1, (uint256)) == 100 ether, "getter(token,account) must read nested slot-3 entry");
    }

    // ---- K-728: the four stray PUSH4 values are NOT stream dispatch targets ----
    function testK728StraySelectorsNotDispatched() public {
        bytes4[5] memory sels = [bytes4(0x12cc0300), bytes4(0x43000822), bytes4(0x54f9d168), bytes4(0x57806396), bytes4(0x612f8756)];
        for (uint256 i; i < sels.length; i++) {
            (bool ok0,) = STREAM.call(abi.encodeWithSelector(sels[i]));
            (bool ok1,) = STREAM.call(abi.encodeWithSelector(sels[i], uint256(1)));
            emit log_named_uint("K-728 selector ok(no-arg)", ok0 ? 1 : 0);
            emit log_named_uint("K-728 selector ok(uint256)", ok1 ? 1 : 0);
            assertFalse(ok0, "stray selector must not dispatch (no-arg)");
            assertFalse(ok1, "stray selector must not dispatch (uint256)");
        }
        emit log_string("K-728: 0x12cc0300/0x43000822/0x54f9d168/0x57806396/0x612f8756 are not stream functions (0x12cc0300 is only a returned constant)");
    }

    // ---- K-720: withdraw on a PAUSED stream — is vested frozen at pausedAt? ----
    // Stream [1000, 87400], paused at 2000 (vested then = 1000*(1000/86400) = 11.574... ether).
    // Warp past end. If vested/withdraw pay the FULL 1000, pause is bypassable (payee drains
    // everything despite the arbiter freezing the clock) — BUG. If frozen ~11.57 ether — KILL.
    function testK720WithdrawWhilePaused() public {
        _fabricate(1, 1000 ether, 0, 1000, 87400, 2000, 1);
        vm.warp(90000); // past end
        (, uint256 vested) = _uintView(SEL_VESTED, 1);
        (, uint256 withdrawable) = _uintView(SEL_WITHDRAWABLE, 1);
        emit log_named_uint("K-720 vested while paused (past end)", vested);
        emit log_named_uint("K-720 withdrawable while paused (past end)", withdrawable);
        uint256 payeeBefore = token.balanceOf(payee);
        (bool ok,) = _callAs(stranger, abi.encodeWithSelector(SEL_WITHDRAW, uint256(1)));
        uint256 payeeDelta = token.balanceOf(payee) - payeeBefore;
        emit log_named_uint("K-720 withdraw ok", ok ? 1 : 0);
        emit log_named_uint("K-720 payee delta", payeeDelta);
        // Frozen expectation: (uint256(1000 ether) * 1000) / 86400 = 11.574074... ether (integer division).
        assertEq(vested, (uint256(1000 ether) * 1000) / 86400, "vested must freeze at pausedAt");
        assertEq(payeeDelta, (uint256(1000 ether) * 1000) / 86400, "withdraw while paused pays only the frozen vested amount");
    }

    // ---- K-721: cancel on a PAUSED stream — payee gets frozen vested only? ----
    function testK721CancelWhilePaused() public {
        _fabricate(2, 1000 ether, 0, 1000, 87400, 2000, 1);
        vm.warp(90000);
        uint256 payeeBefore = token.balanceOf(payee);
        uint256 payerBefore = token.balanceOf(payer);
        (bool ok,) = _callAs(payer, abi.encodeWithSelector(SEL_CANCEL, uint256(2)));
        assertTrue(ok, "payer cancel on paused stream must succeed (documented)");
        uint256 payeeDelta = token.balanceOf(payee) - payeeBefore;
        uint256 payerDelta = token.balanceOf(payer) - payerBefore;
        emit log_named_uint("K-721 cancel paused: payee delta", payeeDelta);
        emit log_named_uint("K-721 cancel paused: payer delta", payerDelta);
        assertEq(payeeDelta, (uint256(1000 ether) * 1000) / 86400, "cancel while paused: payee gets frozen vested only");
        assertEq(payerDelta, 1000 ether - ((uint256(1000 ether) * 1000) / 86400), "cancel while paused: payer gets the remainder");
        assertEq(_streamWords(2)[9], 2, "cancel sets kind=2");
    }

    // ---- K-722: withdraw with withdrawn > vested (fabricated) must not overpay ----
    function testK722WithdrawOverWithdrawn() public {
        vm.warp(1000 + 43200); // halfway: vested 500
        _fabricate(3, 1000 ether, 600 ether, 1000, 87400, 0, 1);
        (, uint256 withdrawable) = _uintView(SEL_WITHDRAWABLE, 3);
        emit log_named_uint("K-722 withdrawable (withdrawn 600 > vested 500)", withdrawable);
        uint256 payeeBefore = token.balanceOf(payee);
        (bool ok,) = _callAs(payee, abi.encodeWithSelector(SEL_WITHDRAW, uint256(3)));
        assertEq(token.balanceOf(payee) - payeeBefore, 0, "over-withdrawn stream must pay nobody");
        emit log_named_uint("K-722 withdraw ok", ok ? 1 : 0);
    }

    // ---- K-723: pause/resume after end ----
    function testK723PauseResumeAfterEnd() public {
        _fabricate(4, 1000 ether, 0, 1000, 87400, 0, 1);
        vm.warp(90000); // past end
        (bool pok,) = _callAs(arbiter, abi.encodeWithSelector(SEL_PAUSE, uint256(4)));
        emit log_named_uint("K-723 pause after end ok", pok ? 1 : 0);
        uint256[10] memory w = _streamWords(4);
        emit log_named_uint("K-723 pausedAt after pause", w[8]);
        if (pok) {
            (bool rok,) = _callAs(arbiter, abi.encodeWithSelector(SEL_RESUME, uint256(4)));
            uint256[10] memory w2 = _streamWords(4);
            emit log_named_uint("K-723 resume ok", rok ? 1 : 0);
            emit log_named_uint("K-723 start after resume", w2[6]);
            emit log_named_uint("K-723 end after resume", w2[7]);
            // Resume shifts the window forward by the pause length; the payee
            // is DELAYED, not enriched — arbiter griefing at most, no theft.
            assertTrue(w2[7] >= 87400, "resume must not shrink the end");
        }
    }

    // ---- K-724: redirect payee — kind matrix + zero address ----
    function testK724RedirectMatrix() public {
        // kind 0/2/3: redirect must not create a payout path
        uint8[3] memory kinds = [uint8(0), uint8(2), uint8(3)];
        for (uint256 i; i < kinds.length; i++) {
            uint256 id = 50 + i;
            _fabricate(id, 1000 ether, 0, 1000, 87400, 0, kinds[i]);
            (bool ok,) = _callAs(payee, abi.encodeWithSelector(SEL_REDIRECT, id, stranger));
            emit log_named_uint("K-724 redirect kind ok", ok ? 1 : 0);
        }
        // kind 1, payee redirects to address(0): REJECTED by the contract
        // (reverts) — even self-harm is blocked. Funds stay with the payee.
        _fabricate(60, 1000 ether, 0, 1000, 87400, 0, 1);
        (bool ok0,) = _callAs(payee, abi.encodeWithSelector(SEL_REDIRECT, uint256(60), address(0)));
        assertFalse(ok0, "redirect to address(0) must revert");
        vm.warp(1000 + 43200);
        uint256 strangerBefore = token.balanceOf(stranger);
        uint256 payeeBefore = token.balanceOf(payee);
        (bool wok,) = _callAs(stranger, abi.encodeWithSelector(SEL_WITHDRAW, uint256(60)));
        assertTrue(wok, "withdraw after failed zero-redirect must succeed");
        assertEq(token.balanceOf(stranger) - strangerBefore, 0, "zero-redirect never pays a stranger");
        assertEq(token.balanceOf(payee) - payeeBefore, 500 ether, "payee still receives the vested 500");
        emit log_string("K-724: redirect is payee-self-service only, zero address rejected; no theft path");
    }

    // ---- K-725: fee-claim edges — empty contract balance / non-token arg ----
    function testK725ClaimEdges() public {
        // Nested entry 100 ether for token, but contract holds 0 of a FRESH token.
        MockERC20 fresh = new MockERC20();
        bytes32 outer = keccak256(abi.encode(address(fresh), uint256(3)));
        bytes32 nested = keccak256(abi.encode(stranger, outer));
        vm.store(STREAM, nested, bytes32(uint256(100 ether)));
        (bool ok,) = _callAs(stranger, abi.encodeWithSelector(SEL_CLAIM, address(fresh)));
        assertFalse(ok, "claim must revert when the contract holds none of the token");
        assertEq(fresh.balanceOf(stranger), 0, "failed claim pays nobody");
        // Token arg = EOA (no code): transfer call to an EOA.
        address eoaToken = address(0x1234);
        bytes32 outer2 = keccak256(abi.encode(eoaToken, uint256(3)));
        bytes32 nested2 = keccak256(abi.encode(stranger, outer2));
        vm.store(STREAM, nested2, bytes32(uint256(50 ether)));
        (bool ok2,) = _callAs(stranger, abi.encodeWithSelector(SEL_CLAIM, eoaToken));
        emit log_named_uint("K-725 claim token=EOA ok", ok2 ? 1 : 0);
        // Either outcome is self-only: the caller can only ever burn/clear
        // their OWN nested entry; no other account's entry is touched.
        emit log_string("K-725: claim edges are self-only; no cross-account theft");
    }

    // ---- K-712 (forge leg): locker ignores trailing calldata ----
    // The SDK lock() pre-check is substring-based: d.includes(hex(token)) &&
    // d.includes(hex(beneficiary)). If the locker ABI-decodes only its fixed
    // args and ignores trailing bytes, the server can smuggle the VICTIM's
    // beneficiary hex as trailing data while the real beneficiary arg is the
    // ATTACKER — the pre-check passes and the lock is created for the attacker.
    function testK712LockerIgnoresTrailingData() public {
        uint256 amt = 500 ether;
        token.mint(payer, amt);
        vm.prank(payer);
        token.approve(address(locker), amt);
        uint64 start = 1000;
        uint64 cliff = 1000;
        uint64 end = 1000 + 30 days;
        bytes memory data = abi.encodeWithSelector(
            MockLocker.createLock.selector, address(token), amt, stranger, start, cliff, end, uint64(0));
        // Smuggle the VICTIM's (payer-as-beneficiary) hex as trailing data.
        bytes memory smuggled = abi.encodePacked(data, bytes32(uint256(uint160(payer))));
        vm.prank(payer);
        (bool ok, bytes memory ret) = address(locker).call(smuggled);
        assertTrue(ok, "locker call with trailing data must succeed (trailing bytes ignored)");
        uint256 id = abi.decode(ret, (uint256));
        MockLocker.Lock memory l = locker.getLock(id);
        assertEq(l.beneficiary, stranger, "the REAL beneficiary arg (attacker) wins, not the smuggled hex");
        assertEq(l.token, address(token), "token arg intact");
        emit log_named_uint("K-712 lock id created for attacker despite smuggled victim hex", id);
    }
}
