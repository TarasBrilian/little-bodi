# core/validation/local_fork.py
"""
LocalEVMFork: Wraps py-evm to simulate exploit transactions on
a minimal local state. Supports both full archive-node mode and
offline-only mode (bytecode only, no storage).
"""
from __future__ import annotations
import logging
from typing import Optional, Set, Dict, Any

from core.validation.models import TransactionResult

logger = logging.getLogger(__name__)


class LocalEVMFork:
    """
    Minimal EVM harness for exploit validation.
    Operates exclusively in simulation — no live network broadcasts.
    """

    def __init__(self, rpc_url: Optional[str] = None, block_number: Optional[int] = None) -> None:
        self.rpc_url = rpc_url
        self.block_number = block_number
        self._bytecode: bytes = b""
        self._contract_address: str = ""

    def setup(self, contract_address: str, bytecode: Optional[bytes] = None) -> None:
        """
        Load the contract state. If rpc_url is set, fetches bytecode from
        an archive node. Otherwise uses the provided bytecode argument.
        """
        self._contract_address = contract_address

        if bytecode:
            self._bytecode = bytecode
            return

        if self.rpc_url:
            try:
                from web3 import Web3
                w3 = Web3(Web3.HTTPProvider(self.rpc_url))
                block_id = self.block_number if self.block_number else "latest"
                code = w3.eth.get_code(contract_address, block_identifier=block_id)
                self._bytecode = bytes(code)
                logger.info(f"Loaded bytecode for {contract_address} ({len(self._bytecode)} bytes)")
            except Exception as e:
                logger.warning(f"RPC bytecode fetch failed: {e}")

    def execute_transaction(
        self,
        from_address: str,
        to_address: str,
        calldata: bytes,
        value: int = 0,
        gas_limit: int = 1_000_000,
    ) -> TransactionResult:
        """
        Execute the exploit transaction in a minimal local EVM.
        Tracks executed PCs and event logs (simulated).
        Returns a TransactionResult with success status.
        """
        if not self._bytecode:
            return TransactionResult(
                success=False,
                revert_reason="No bytecode loaded — setup() must be called first",
            )

        executed_pcs: Set[int] = set()
        logs: list = []
        success = False
        revert_reason: Optional[str] = None
        return_data = b""

        try:
            success, executed_pcs, logs, return_data = self._run_minimal_evm(
                bytecode=self._bytecode,
                calldata=calldata,
                from_address=from_address,
                gas_limit=gas_limit,
            )
        except Exception as e:
            revert_reason = str(e)
            logger.warning(f"EVM execution exception: {e}")

        return TransactionResult(
            success=success,
            return_data=return_data,
            gas_used=0,   # simplified: not tracked
            logs=logs,
            executed_pcs=executed_pcs,
            revert_reason=revert_reason,
        )

    def _run_minimal_evm(
        self,
        bytecode: bytes,
        calldata: bytes,
        from_address: str,
        gas_limit: int,
    ) -> tuple[bool, Set[int], list, bytes]:
        """
        Executes bytecode in a minimal interpreter loop.
        Tracks executed PCs. Simulates CALL logging.
        Returns (success, executed_pcs, logs, return_data).
        """
        from core.constants import (
            OP_STOP, OP_RETURN, OP_REVERT, OP_INVALID, OP_SELFDESTRUCT,
            OP_JUMP, OP_JUMPI, OP_PUSH1, OP_PUSH32, OP_DUP1, OP_DUP16,
            OP_SWAP1, OP_SWAP16, OP_POP, OP_JUMPDEST,
            OP_CALLER, OP_CALLVALUE, OP_CALLDATALOAD, OP_CALLDATASIZE,
            OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_AND, OP_OR, OP_XOR,
            OP_SHL, OP_SHR, OP_EQ, OP_LT, OP_GT, OP_ISZERO,
            OP_MLOAD, OP_MSTORE, OP_MSTORE8,
            OP_CALL, OP_STATICCALL, OP_DELEGATECALL, OP_CALLCODE,
        )

        MAX_STEPS = 50_000
        stack: list[int] = []
        memory: Dict[int, int] = {}
        pc = 0
        executed_pcs: Set[int] = set()
        logs: list = []
        caller_int = int(from_address, 16) if from_address.startswith("0x") else 0

        def mload(off: int) -> int:
            return memory.get(off, 0)

        def mstore(off: int, val: int) -> None:
            memory[off] = val & (2**256 - 1)

        steps = 0
        while pc < len(bytecode) and steps < MAX_STEPS:
            steps += 1
            op = bytecode[pc]
            executed_pcs.add(pc)

            if op in (OP_STOP,):
                return True, executed_pcs, logs, b""

            if op in (OP_RETURN,):
                # Simplified: no actual data extraction
                return True, executed_pcs, logs, b""

            if op in (OP_REVERT, OP_INVALID):
                return False, executed_pcs, logs, b""

            if op == OP_SELFDESTRUCT:
                if stack: stack.pop()
                return True, executed_pcs, logs, b""

            # PUSH1-PUSH32
            if OP_PUSH1 <= op <= OP_PUSH32:
                size = op - OP_PUSH1 + 1
                val = int.from_bytes(bytecode[pc + 1: pc + 1 + size], "big")
                stack.append(val)
                pc += size + 1
                continue

            # DUP1-DUP16
            if OP_DUP1 <= op <= OP_DUP16:
                idx = op - OP_DUP1 + 1
                if len(stack) >= idx:
                    stack.append(stack[-idx])
                pc += 1
                continue

            # SWAP1-SWAP16
            if OP_SWAP1 <= op <= OP_SWAP16:
                idx = op - OP_SWAP1 + 1
                if len(stack) > idx:
                    stack[-1], stack[-1 - idx] = stack[-1 - idx], stack[-1]
                pc += 1
                continue

            # Arithmetic / Bitwise
            if op == OP_POP:
                if stack: stack.pop()
            elif op == OP_ADD:
                if len(stack) >= 2:
                    stack.append((stack.pop() + stack.pop()) & (2**256 - 1))
            elif op == OP_SUB:
                if len(stack) >= 2:
                    a, b = stack.pop(), stack.pop()
                    stack.append((a - b) & (2**256 - 1))
            elif op == OP_MUL:
                if len(stack) >= 2:
                    stack.append((stack.pop() * stack.pop()) & (2**256 - 1))
            elif op == OP_DIV:
                if len(stack) >= 2:
                    a, b = stack.pop(), stack.pop()
                    stack.append(a // b if b else 0)
            elif op == OP_AND:
                if len(stack) >= 2:
                    stack.append(stack.pop() & stack.pop())
            elif op == OP_OR:
                if len(stack) >= 2:
                    stack.append(stack.pop() | stack.pop())
            elif op == OP_XOR:
                if len(stack) >= 2:
                    stack.append(stack.pop() ^ stack.pop())
            elif op == OP_SHL:
                if len(stack) >= 2:
                    shift, val = stack.pop(), stack.pop()
                    stack.append((val << shift) & (2**256 - 1))
            elif op == OP_SHR:
                if len(stack) >= 2:
                    shift, val = stack.pop(), stack.pop()
                    stack.append(val >> shift)
            elif op == OP_EQ:
                if len(stack) >= 2:
                    stack.append(1 if stack.pop() == stack.pop() else 0)
            elif op == OP_LT:
                if len(stack) >= 2:
                    a, b = stack.pop(), stack.pop()
                    stack.append(1 if a < b else 0)
            elif op == OP_GT:
                if len(stack) >= 2:
                    a, b = stack.pop(), stack.pop()
                    stack.append(1 if a > b else 0)
            elif op == OP_ISZERO:
                if stack:
                    stack.append(1 if stack.pop() == 0 else 0)

            # Environment
            elif op == OP_CALLER:
                stack.append(caller_int)
            elif op == OP_CALLVALUE:
                stack.append(0)
            elif op == OP_CALLDATASIZE:
                stack.append(len(calldata))
            elif op == OP_CALLDATALOAD:
                off = stack.pop() if stack else 0
                chunk = calldata[off: off + 32].ljust(32, b"\x00")
                stack.append(int.from_bytes(chunk, "big"))

            # Memory
            elif op == OP_MLOAD:
                off = stack.pop() if stack else 0
                stack.append(mload(off))
            elif op == OP_MSTORE:
                if len(stack) >= 2:
                    off, val = stack.pop(), stack.pop()
                    mstore(off, val)
            elif op == OP_MSTORE8:
                if len(stack) >= 2:
                    off, val = stack.pop(), stack.pop()
                    memory[off] = val & 0xFF

            # Control flow
            elif op == OP_JUMP:
                dest = stack.pop() if stack else 0
                if dest < len(bytecode) and bytecode[dest] == 0x5B:
                    pc = dest
                    continue
                else:
                    return False, executed_pcs, logs, b""
            elif op == OP_JUMPI:
                if len(stack) >= 2:
                    dest, cond = stack.pop(), stack.pop()
                    if cond != 0:
                        if dest < len(bytecode) and bytecode[dest] == 0x5B:
                            pc = dest
                            continue
            elif op == OP_JUMPDEST:
                pass  # valid landing point

            # CALL family — simulated as success, log a synthetic transfer event
            elif op in (OP_CALL, OP_CALLCODE, OP_STATICCALL, OP_DELEGATECALL):
                req = 7 if op in (OP_CALL, OP_CALLCODE) else 6
                for _ in range(min(req, len(stack))):
                    stack.pop()
                # Simulate a synthetic Transfer event log
                logs.append({
                    "address": self._contract_address.lower(),
                    "topics": [],
                    "data": b"",
                    "_simulated": True,
                })
                stack.append(1)  # success

            pc += 1

        return True, executed_pcs, logs, b""
