#!/usr/bin/env python3
"""
_step4_calls.py — STEP 4 diagnostic:
  - How many CALL opcodes exist in the deobfuscated CFG?
  - What is pushed onto the stack as the target address before each CALL?
  - Is the target address tainted (symbolic) or concrete (hardcoded)?
  - Does it match any known ERC-20 token address?

Run from project root:
    source .env && python3 scripts/_step4_calls.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv

load_dotenv()

from web3 import Web3

from core.bytecode_analysis.engine import BytecodeAnalysisEngine
from core.constants import TRACKED_TOKENS
from core.deobfuscation.engine import DeobfuscationEngine
from core.pipeline import AnalysisConfig, AnalysisContext

# ── config ───────────────────────────────────────────────────────────────────
ADDRESS = "0x00000000003b3cc22aF3aE1EAc0440BcEe416B40"
CALL_OPCODES = {
    0xF1: "CALL",
    0xF2: "CALLCODE",
    0xF4: "DELEGATECALL",
    0xFA: "STATICCALL",
}
KNOWN_ERC20_LOWER = {a.lower() for a in TRACKED_TOKENS}

# ── 1. fetch + analyse ────────────────────────────────────────────────────────
rpc_url = os.getenv("EVM_RPC_URL", "")
if not rpc_url:
    print("ERROR: EVM_RPC_URL not set")
    sys.exit(1)

w3 = Web3(Web3.HTTPProvider(rpc_url))
raw = w3.eth.get_code(Web3.to_checksum_address(ADDRESS))
bytecode = bytes(raw)
print(f"[fetch]  bytecode = {len(bytecode)} bytes")

config = AnalysisConfig(rpc_url=rpc_url)
ctx = AnalysisContext(
    bytecode=bytecode,
    contract_address=ADDRESS,
    chain_id=1,
    block_number=None,
    config=config,
)
ctx = BytecodeAnalysisEngine(config).execute(ctx)
ctx = DeobfuscationEngine(config).execute(ctx)

cfg = ctx.deobfuscated_cfg or ctx.cfg

# ── 2. collect all CALL instructions ─────────────────────────────────────────
call_sites = []  # list of (pc, mnemonic, block_start, instr_index, block_instrs)
for block_start, block in cfg.blocks.items():
    instrs = block.instructions
    for idx, instr in enumerate(instrs):
        if instr.opcode in CALL_OPCODES:
            call_sites.append(
                (instr.pc, CALL_OPCODES[instr.opcode], block_start, idx, instrs)
            )

print(f"\nTotal CALL opcodes in deobfuscated CFG: {len(call_sites)}")
print(
    f"  breakdown: { {mn: sum(1 for _,m,*_ in call_sites if m==mn) for mn in CALL_OPCODES.values()} }"
)

# ── 3. for each CALL, show the instruction window leading up to it ────────────
print("\n--- CALL sites with surrounding context (up to 5 instructions back) ---")
for pc, mnemonic, block_start, idx, instrs in call_sites[:30]:  # cap at 30
    window = instrs[max(0, idx - 5) : idx + 1]
    print(f"\n  [{mnemonic}] at PC={pc}  (block starts at PC={block_start})")
    for w in window:
        operand_str = ("0x" + w.operand.hex()) if w.operand else ""
        marker = "  <<<" if w.pc == pc else ""
        print(f"    PC={w.pc:5d}  {w.mnemonic:<16} {operand_str}{marker}")

    # Heuristic: find the instruction that puts the target address on the stack.
    # In EVM, CALL pops [gas, to, value, argsOffset, argsSize, retOffset, retSize].
    # 'to' is the second item popped, i.e. the second-from-top when CALL executes.
    # Most commonly: PUSH20 <addr> somewhere in the window is the concrete target.
    push20s = [
        w
        for w in window
        if 0x60 <= w.opcode <= 0x7F and w.operand and len(w.operand) == 20
    ]
    push2s = [w for w in window if w.opcode == 0x61 and w.operand]  # PUSH2
    sloads = [w for w in window if w.opcode == 0x54]  # SLOAD (storage-sourced addr)
    mloads = [w for w in window if w.opcode == 0x51]  # MLOAD
    calldataload = [w for w in window if w.opcode == 0x35]  # CALLDATALOAD

    if push20s:
        for p in push20s:
            addr_int = int.from_bytes(p.operand, "big")
            addr_hex = f"0x{addr_int:040x}"
            is_erc20 = addr_hex.lower() in KNOWN_ERC20_LOWER
            print(f"    → concrete target: {addr_hex}  known_erc20={is_erc20}")
    elif calldataload:
        print(f"    → target likely from CALLDATALOAD (calldata-controlled)")
    elif sloads:
        print(f"    → target likely from SLOAD (storage-sourced)")
    elif mloads:
        print(f"    → target likely from MLOAD (memory-sourced)")
    else:
        print(f"    → target source: unknown / computed from stack")

# ── 4. summary: how many targets are concrete vs symbolic ────────────────────
print("\n--- Target address source summary ---")
concrete_erc20 = 0
concrete_other = 0
from_calldata = 0
from_storage = 0
from_memory = 0
unknown = 0

for pc, mnemonic, block_start, idx, instrs in call_sites:
    window = instrs[max(0, idx - 5) : idx + 1]
    push20s = [
        w
        for w in window
        if 0x60 <= w.opcode <= 0x7F and w.operand and len(w.operand) == 20
    ]
    calldataload = [w for w in window if w.opcode == 0x35]
    sloads = [w for w in window if w.opcode == 0x54]
    mloads = [w for w in window if w.opcode == 0x51]

    if push20s:
        for p in push20s:
            addr_hex = f"0x{int.from_bytes(p.operand, 'big'):040x}"
            if addr_hex.lower() in KNOWN_ERC20_LOWER:
                concrete_erc20 += 1
            else:
                concrete_other += 1
    elif calldataload:
        from_calldata += 1
    elif sloads:
        from_storage += 1
    elif mloads:
        from_memory += 1
    else:
        unknown += 1

print(f"  concrete → known ERC-20 token : {concrete_erc20}")
print(f"  concrete → other address       : {concrete_other}")
print(f"  from CALLDATALOAD (tainted)    : {from_calldata}")
print(f"  from SLOAD (storage)           : {from_storage}")
print(f"  from MLOAD (memory)            : {from_memory}")
print(f"  unknown / computed             : {unknown}")

# ── 5. taint check: what does the symbolic interpreter see as `to`? ───────────
# Reproduce one CALL encounter from a short symbolic run to inspect target_address type
print(
    "\n--- Sampling one symbolic execution trace to inspect CallEncounter.target_address ---"
)
import z3

from core.symbolic_execution.interpreter import SymbolicEVMInterpreter
from core.symbolic_execution.state import SymbolicState

byt = ctx.instrumented_bytecode or bytecode
mini_config = AnalysisConfig(
    rpc_url=rpc_url,
    use_concolic=False,
    max_symbolic_paths=50,
    max_path_depth=60,
    timeout_per_contract=20,
)
interp = SymbolicEVMInterpreter(byt, cfg, mini_config)
traces = interp.execute(SymbolicState(pc=0))

all_calls = [c for t in traces for c in t.calls_encountered]
print(f"  CallEncounters in {len(traces)} traces: {len(all_calls)}")

for i, c in enumerate(all_calls[:10]):
    tgt = c.target_address
    tgt_type = type(tgt).__name__
    is_int = isinstance(tgt, int)
    is_z3 = isinstance(tgt, z3.ExprRef)
    taint = traces[0].taint_map.is_tainted(tgt) if is_z3 else False
    addr_hex = f"0x{tgt:040x}" if is_int else str(tgt)[:60]
    is_erc20 = (f"0x{tgt:040x}".lower() in KNOWN_ERC20_LOWER) if is_int else False
    print(
        f"  call[{i}] PC={c.pc}  target={addr_hex}"
        f"  type={tgt_type}  is_z3={is_z3}  tainted={taint}  known_erc20={is_erc20}"
    )

print("\nDone.")
