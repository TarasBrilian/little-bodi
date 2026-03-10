#!/usr/bin/env python3
"""
_test_fix.py — one-shot test runner to verify pruned_empty_block fix.
Run from the project root:
    source .env && python3 scripts/_test_fix.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web3 import Web3
from dotenv import load_dotenv

load_dotenv()

ADDRESS = "0x00000000003b3cc22aF3aE1EAc0440BcEe416B40"

# ── 1. Fetch bytecode ────────────────────────────────────────────────────────
rpc_url = os.getenv("EVM_RPC_URL", "")
if not rpc_url:
    print("ERROR: EVM_RPC_URL not set in environment / .env")
    sys.exit(1)

w3 = Web3(Web3.HTTPProvider(rpc_url))
raw = w3.eth.get_code(Web3.to_checksum_address(ADDRESS))
bytecode_hex = raw.hex()
bytecode_bytes = bytes.fromhex(bytecode_hex.removeprefix("0x"))
print(f"[fetch]  bytecode = {len(bytecode_bytes)} bytes")

if not bytecode_bytes:
    print("ERROR: empty bytecode returned from RPC")
    sys.exit(1)

# ── 2. Run analysis with tight limits ───────────────────────────────────────
from core.pipeline import AnalysisConfig, AnalysisPipeline

config = AnalysisConfig(
    rpc_url=rpc_url,
    use_concolic=False,  # pure symbolic — no seed generation
    max_symbolic_paths=300,
    max_path_depth=100,
    timeout_per_contract=60,
)

pipeline = AnalysisPipeline(config)
ctx = pipeline.run(
    bytecode=bytecode_bytes,
    contract_address=ADDRESS,
)

# ── 3. Extract stats from interpreter (already printed by DEBUG line) ────────
# The interpreter prints "DEBUG: Final stats = {...}" to stdout.
# We also pull high-level numbers from the context for a clean summary.

print()
print("=" * 60)
print("RESULTS SUMMARY")
print("=" * 60)
print(f"  execution_traces  : {len(ctx.execution_traces)}")
print(f"  potential_vulns   : {len(ctx.potential_vulnerabilities)}")
print(f"  coverage_before   : {ctx.coverage_before:.1f}%")
print(f"  coverage_after    : {ctx.coverage_after:.1f}%")
print(f"  is_obfuscated     : {ctx.is_obfuscated}")
print(f"  indirect_jumps    : {len(ctx.indirect_jumps)}")
if ctx.deobfuscated_cfg:
    print(f"  cfg_blocks        : {len(ctx.deobfuscated_cfg.blocks)}")
print(f"  errors            : {ctx.errors}")
print("=" * 60)

# ── 4. Pass/fail check ───────────────────────────────────────────────────────
print()
print("PASS/FAIL checks:")

# The interpreter prints "DEBUG: Final stats = {...}" — capture it by re-running
# a tiny inline execution so we can inspect the dict directly.
from core.symbolic_execution.interpreter import SymbolicEVMInterpreter
from core.symbolic_execution.state import SymbolicState
import io, contextlib

cfg = ctx.deobfuscated_cfg or ctx.cfg
byt = ctx.instrumented_bytecode or bytecode_bytes

interp = SymbolicEVMInterpreter(byt, cfg, config)

# Monkey-patch execute to capture stats
_original_execute = interp.execute
captured_stats = {}


def _patched_execute(initial_state):
    traces = _original_execute(initial_state)
    return traces


# Re-run a very short execution just to capture stats cleanly
config2 = AnalysisConfig(
    rpc_url=rpc_url,
    use_concolic=False,
    max_symbolic_paths=300,
    max_path_depth=100,
    timeout_per_contract=30,
)
interp2 = SymbolicEVMInterpreter(byt, cfg, config2)

buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    traces2 = interp2.execute(SymbolicState(pc=0))

output = buf.getvalue()
print(output.strip())  # show the "DEBUG: Final stats = ..." line

# Parse the stats dict from the printed line
import ast, re

m = re.search(r"Final stats\s*=\s*(\{.*\})", output)
if m:
    stats = ast.literal_eval(m.group(1))
    print()
    ok_empty = stats.get("pruned_empty_block", -1) == 0
    ok_compl = stats.get("completed", 0) > 10
    ok_paths = (
        stats.get("completed", 0)
        + stats.get("pruned_depth", 0)
        + stats.get("pruned_unsat", 0)
    ) > 50

    print(
        f"  [{'PASS' if ok_empty else 'FAIL'}] pruned_empty_block == 0  "
        f"(got {stats.get('pruned_empty_block')})"
    )
    print(
        f"  [{'PASS' if ok_compl else 'FAIL'}] completed > 10           "
        f"(got {stats.get('completed')})"
    )
    print(
        f"  [{'PASS' if ok_paths else 'FAIL'}] paths_explored > 50      "
        f"(got {stats.get('completed', 0) + stats.get('pruned_depth', 0) + stats.get('pruned_unsat', 0)})"
    )
    print()
    if ok_empty and ok_compl and ok_paths:
        print("ALL CHECKS PASSED ✓")
        sys.exit(0)
    else:
        print("SOME CHECKS FAILED ✗")
        sys.exit(1)
else:
    print("WARNING: could not parse stats line from interpreter output")
    print("Raw output was:")
    print(output)
    sys.exit(1)
