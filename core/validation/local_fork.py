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
        Execute the exploit transaction in a local py-evm fork.
        Tracks real gas usage and extracts event logs.
        """
        if not self._bytecode:
            return TransactionResult(
                success=False,
                revert_reason="No bytecode loaded — setup() must be called first",
            )

        from eth.chains.mainnet import MainnetChain
        from eth.db.atomic import AtomicDB
        from eth_utils import to_canonical_address, to_wei, decode_hex
        from eth.vm.forks.shanghai import ShanghaiVM

        # 1. Define a custom chain that forces Shanghai VM from block 0
        # This ensures opcodes like SHR (0x1c) are supported.
        class ShanghaiChain(MainnetChain):
            vm_configuration = (
                (0, ShanghaiVM),
            )

        # 2. Initialize DB and Chain
        db = AtomicDB()
        genesis_params = {
            "difficulty": 0,
            "gas_limit": 30000000,
            "timestamp": 0,
            "coinbase": b'\x00' * 20,
            "extra_data": b'',
            "mix_hash": b'\x00' * 32,
            "nonce": b'\x00' * 8,
        }
        chain = ShanghaiChain.from_genesis(db, genesis_params)

        # 3. Setup State (Adversary balance + Victim bytecode)
        header = chain.get_canonical_head()
        vm = chain.get_vm(header)
        state = vm.state
        
        adversary_can = to_canonical_address(from_address)
        victim_can = to_canonical_address(to_address)
        
        # Give adversary 1000 ETH
        state.set_balance(adversary_can, to_wei(1000, 'ether'))
        state.set_code(victim_can, self._bytecode)
        
        # 3. Build Transaction
        tx = vm.create_unsigned_transaction(
            nonce=state.get_nonce(adversary_can),
            gas_price=to_wei(1, 'gwei'),
            gas=gas_limit,
            to=victim_can,
            value=value,
            data=calldata,
        )
        
        from eth_keys import keys
        
        # Hardhat account #0 private key
        pk_hex = 'ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
        priv_key = keys.PrivateKey(decode_hex(pk_hex))
        signed_tx = tx.as_signed_transaction(priv_key)
        
        try:
            # Applying signed transaction directly via the State object
            computation = state.apply_transaction(signed_tx)
            
            success = not computation.is_error
            revert_reason = None
            if computation.is_error:
                # Try to decode standard Error(string) or just use the raw bytes
                if computation.output and computation.output.startswith(b'\x08\xc3y\xa0'):
                    try:
                        # Skip 4-byte selector and first 32-byte offset
                        reason_bytes = computation.output[36:]
                        # Next 32 bytes is length
                        reason_len = int.from_bytes(reason_bytes[:32], 'big')
                        revert_reason = reason_bytes[32:32+reason_len].decode('utf-8', errors='ignore')
                    except:
                        revert_reason = computation.output.hex()
                else:
                    revert_reason = str(computation.error) or computation.output.hex()
            
            # Extract gas and logs
            # computation.get_gas_used() usually excludes intrinsic gas (21k + calldata)
            # when called via state.apply_transaction directly.
            gas_used = computation.get_gas_used() + signed_tx.intrinsic_gas

            log_entries = computation.get_log_entries()
            
            logs = []
            for log in log_entries:
                # Log entry is (address, topics, data)
                logs.append({
                    "address": "0x" + log[0].hex(),
                    "topics": ["0x" + t.hex() for t in log[1]],
                    "data": "0x" + log[2].hex(),
                })
            
            return_data = computation.output

            return TransactionResult(
                success=success,
                return_data=return_data,
                gas_used=gas_used,
                logs=logs,
                executed_pcs=set(),
                revert_reason=revert_reason,
            )
        except Exception as e:
            logger.warning(f"py-evm execution failed: {e}")
            return TransactionResult(
                success=False,
                revert_reason=str(e),
                gas_used=0,
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
