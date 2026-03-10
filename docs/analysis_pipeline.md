# analysis_pipeline.md — Little Bodi Full Analysis Pipeline

## Overview

The pipeline consists of 3 main stages (based on the SKANF paper), each composed of several sub-steps. Each step can fail independently with defined fallback behaviors.

---

## Stage A: Bytecode Analysis & Deobfuscation

### Step A1 — Bytecode Ingestion & Validation

**Input**: raw bytecode (hex string or bytes)  
**Output**: validated `bytes` + metadata

```
Bytecode → Strip 0x prefix → Validate hex → Convert to bytes
         → Check minimum length (>= 1 byte)
         → Check that it does not exceed EVM limit (24KB = 24576 bytes)
```

**Edge cases**:
- Empty bytecode: STOP instruction only, skip to report
- Pure proxy contract: mark as "proxy, skip analysis"

---

### Step A2 — Disassembly

**Input**: bytecode bytes  
**Output**: `DisassemblyResult` with instruction list and JUMPDEST set

Correct disassembly algorithm for EVM:
```
i = 0
while i < len(bytecode):
    opcode = bytecode[i]
    
    if opcode is PUSH1-PUSH32 (0x60-0x7F):
        push_size = opcode - 0x60 + 1
        operand = bytecode[i+1 : i+1+push_size]
        emit Instruction(pc=i, opcode=opcode, operand=operand)
        i += 1 + push_size
    
    elif opcode == JUMPDEST (0x5B):
        emit Instruction(pc=i, ...)
        jumpdests.add(i)  # This PC is valid as a jump target
        i += 1
    
    else:
        emit Instruction(pc=i, opcode=opcode)
        i += 1
```

**Critical**: JUMPDEST is only valid if it is not inside PUSH data. The above algorithm handles this by skipping PUSH operands.

---

### Step A3 — CFG Construction

**Input**: `DisassemblyResult`  
**Output**: `ControlFlowGraph`

Basic block splitting rules:
- A new block starts AFTER: `JUMP`, `JUMPI`, `STOP`, `RETURN`, `REVERT`, `INVALID`, `SELFDESTRUCT`
- A new block starts AT: every `JUMPDEST`

Edge construction:
- After `STOP/RETURN/REVERT/INVALID`: terminal, no successors
- After `JUMP`: successor = unknown (indirect) or known (if top-of-stack was a previous PUSH constant)
- After `JUMPI`: two successors — fall-through (PC+1) and taken (top-of-stack)
- Others: fall-through to the next block

---

### Step A4 — Indirect Jump Identification

**Input**: `ControlFlowGraph`  
**Output**: `list[IndirectJump]`

For each JUMP/JUMPI in the CFG, perform backward slicing:
1. Find the value on top-of-stack when JUMP is executed.
2. Trace backward through instructions.
3. If the value originates from: CALLDATALOAD, CALLDATACOPY, MLOAD, SLOAD → this is an **indirect jump**.
4. If the value is a PUSH constant → this is a **direct jump** (already ok).

Record the set `J = {(jump_pc, stack_var_name), ...}`.

---

### Step A5 — Branch Table Injection

**Input**: bytecode, `set[int]` (all JUMPDESTs), `list[IndirectJump]`  
**Output**: deobfuscated bytecode representation (CFG-level, not raw bytes)

For each indirect jump in `J`:
1. Rewrite instructions to PUSH `0xe000` before the JUMP.
2. Build branch table at offset `0xe000`:
   ```
   0xe000: JUMPDEST
   0xe001: DUP1           ; copy destination value
   0xe002: PUSH2 <dst_1>  ; first valid destination
   0xe005: EQ
   0xe006: PUSH2 <goto_1> ; intermediate for dst_1
   0xe009: JUMPI
   0xe00a: DUP1           ; try next
   ...
   ```
3. Build intermediates at `0xf000+`:
   ```
   0xf000: JUMPDEST       ; intermediate for dst_1
   0xf001: POP            ; remove duplicate
   0xf002: PUSH2 <dst_1>
   0xf005: JUMP
   ```
4. Special handling for JUMPI:
   - Insert `SWAP1` before PUSH `0xe000` (preserve condition)
   - Insert `POP` after JUMPI fall-through (cleanup stack)

**Constraint**: Total size of branch table + intermediates must fit between `0xe000` and `0xffff` (8KB space).

---

### Step A6 — Coverage Measurement

**Before**: run reachability analysis on the original CFG, calculate the `%` of blocks reachable from entry points.  
**After**: run reachability analysis on the deobfuscated CFG.

Threshold: if `coverage_before < 50%` and `coverage_after < 50%`, log warning "deobfuscation may have failed or contract has genuinely unreachable code".

---

## Stage B: Vulnerability Detection

### Step B1 — Seed Input Extraction (Concolic Mode)

**Input**: contract address, archive node RPC  
**Output**: `list[SeedInput]`

```
1. Query Etherscan API / RPC for recent transactions to contract_address
2. Filter: successful transactions only (status = 1)
3. For each successful tx:
   a. Replay on archive node at the tx's block_number
   b. Parse ERC-20 Transfer/Approval event logs
   c. If there is an ERC-20 event involving contract_address as 'from':
      → Extract (origin, caller, calldata, value, block_number) as seed
4. Filter: discard seeds with empty calldata
5. Return top-N seeds (default N=50, configurable)
```

**Fallback**: if no seeds are found (inactive contract or RPC unavailable), use symbolic mode (Step B3b).

---

### Step B2 — Concolic Execution

**Input**: deobfuscated bytecode/CFG, `list[SeedInput]`  
**Output**: `list[ExecutionTrace]`

For each seed input:
1. Start execution with concrete values from the seed.
2. At each conditional branch (JUMPI):
   - Concrete execution follows the path taken by the seed.
   - Save the path constraint (symbolic) for the path taken.
3. Upon finding a CALL instruction:
   - Mark as a potential sink.
   - Record all parameters (target, selector, args) along with their symbolic expressions.
4. Continue until STOP/RETURN/REVERT or timeout.
5. Return trace with all discovered CALLs.

**State explosion mitigation** (based on the paper):
- Max 2 visits to the branch table per execution path.
- Prune path if constraints are already unsatisfiable.

---

### Step B3 — Symbolic Execution (Fallback Mode)

**Input**: deobfuscated bytecode/CFG  
**Output**: `list[ExecutionTrace]`

Activated if: concolic execution finds no vulnerabilities, or if no seed inputs exist.

```
1. Enumerate all CALL instructions in the CFG
2. For each CALL:
   a. Use call graph to check if reachable from a public entry point
   b. If reachable, find path in CFG from entry to CALL
   c. Initialize symbolic execution from entry point:
      - calldata = fully symbolic byte string
      - caller = adversary address (config)
      - origin = adversary address (or from seed if available)
3. At each JUMPI: fork execution into two paths
4. Prune if constraints unsatisfiable
5. Prune if path cannot reach target CALL (via CFG lookahead)
6. Stop if max paths or timeout reached
```

---

### Step B4 — Taint Analysis

Performed **on-the-fly** during concolic/symbolic execution.

**Taint sources** (taint initialization):
```python
TAINT_SOURCES = {
    0x35: "CALLDATALOAD",   # taint bytes 0-31 from calldata
    0x37: "CALLDATACOPY",   # taint range from calldata to memory
}
```

**Taint propagation** (conservative — if any input is tainted, output is tainted):
```python
PROPAGATE_TAINT = {
    # Arithmetic
    0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x04: "DIV",
    0x06: "MOD", 0x08: "ADDMOD", 0x09: "MULMOD", 0x0A: "EXP",
    # Bitwise  
    0x10: "LT", 0x11: "GT", 0x13: "EQ",
    0x16: "AND", 0x17: "OR", 0x18: "XOR", 0x19: "NOT",
    0x1A: "BYTE", 0x1B: "SHL", 0x1C: "SHR", 0x1D: "SAR",
    # Stack/Memory copy
    0x80: "DUP1", ..., 0x8F: "DUP16",
    0x51: "MLOAD", 0x52: "MSTORE",
    0x54: "SLOAD",
}
```

**Taint sinks** — checked at CALL:
```
CALL parameters:
  [0] gas         → irrelevant to vulnerability
  [1] target_addr → SINK: check if tainted
  [2] value       → irrelevant for asset theft via ERC-20
  [3] argsOffset  → pointer to calldata, trace to:
       [3+0..3]   → function_selector (4 bytes) → SINK
       [3+4..35]  → arg1/recipient (32 bytes) → SINK
       [3+36..67] → arg2/amount (32 bytes) → SINK
```

---

### Step B5 — Vulnerability Classification

**Input**: one ExecutionTrace with taint info at CALL  
**Output**: `Optional[PotentialVulnerability]`

Decision tree:
```
CALL found in trace
│
├─ target_address tainted?
│   ├─ YES → adversary_controllable_target = True
│   └─ NO  → check if known ERC-20 token address
│             ├─ YES → risky_fixed_target = True
│             └─ NO  → NOT VULNERABLE, skip
│
├─ function_selector tainted?
│   ├─ YES → adversary_controllable_selector = True
│   └─ NO  → check if == 0xa9059cbb (transfer) or 0x095ea7b3 (approve)
│             ├─ YES → risky_fixed_selector = True
│             └─ NO  → NOT VULNERABLE, skip
│
└─ arg1 (bytes 5-36) fully controllable?
    ├─ YES → VULNERABLE → create PotentialVulnerability
    └─ NO  → NOT VULNERABLE, skip (recipient cannot be set to adversary)
```

---

### Step B6 — Preliminary Validation

Before proceeding to exploit generation, verify that the CALL can be triggered:

1. Solve path constraints from PotentialVulnerability using Z3.
2. Construct concrete calldata from solved constraints.
3. Run on local fork (py-evm) with caller = adversary.
4. Check: was the CALL instruction executed? (no need for success or transfer)
5. If yes → proceed to Stage C.
6. If no → mark as false positive, log and skip.

---

## Stage C: Exploit Generation & Validation

### Step C1 — Token Discovery

**Input**: contract address, block number  
**Output**: `list[tuple[token_address, balance]]`

```
1. Query ERC-20 token balance for each token in the risky_tokens config list
2. Also add tokens found in seed input ERC-20 events
3. Filter: tokens with balance > 0 only
4. Sort: descending by balance value (most profitable targets first)
```

---

### Step C2 — Calldata Synthesis

**Input**: `PotentialVulnerability`, target token address, block number  
**Output**: `bytes` (exploit calldata)

```
1. Start from seed_calldata that triggers the vulnerability
2. Identify bytes that must be replaced:
   - target_address bytes → token_address
   - selector bytes → 0xa9059cbb (transfer)
   - recipient bytes → adversary_address
   - amount bytes → full token balance
3. Create Z3 constraint:
   - calldata[target_offset:target_offset+32] == token_address_padded
   - calldata[selector_offset:selector_offset+4] == 0xa9059cbb
   - calldata[recipient_offset:recipient_offset+32] == adversary_address_padded
   - calldata[amount_offset:amount_offset+32] == token_balance
4. Solve with Z3 (path constraints from vulnerability + new constraint)
5. Extract concrete calldata from model
6. Verify: re-run concolic from vulnerable CALL until STOP/RETURN
   with this calldata to ensure execution finishes correctly
```

---

### Step C3 — Exploit Validation

**Input**: `Exploit` object  
**Output**: `ValidatedExploit`

```
1. Setup local fork using py-evm:
   a. Load state from archive node at exploit.block_number
   b. Load contract bytecode, storage, balances

2. Execute exploit transaction:
   - from: exploit.from_address
   - to: exploit.to_address (victim contract)
   - calldata: exploit.calldata
   - value: exploit.value

3. Inspect result:
   a. Transaction status == 1 (success)?
   b. ERC-20 Transfer event emitted?
      - from: victim contract address
      - to: adversary address
      - value: expected amount

4. If both True → ValidatedExploit(success=True)
5. If not → ValidatedExploit(success=False, error=...)

6. Calculate estimated_loss_usd using token price oracle
   (or hardcoded price if offline mode)
```

---

## Error Handling & Fallback Summary

| Step | Error | Fallback |
|---|---|---|
| A2 Disassembly | Invalid bytecode | Abort, report error |
| A3 CFG | Complex graph, OOM | Partial CFG, continue |
| A5 Branch table | Exceeds 0xffff | Log warning, skip deobfuscation |
| B1 Seed extraction | RPC timeout | Skip to symbolic mode |
| B2 Concolic | Path explosion | Activate pruning, then symbolic fallback |
| B3 Symbolic | Timeout | Return partial results |
| B5 Classification | Z3 unsat | Mark as false positive |
| C2 Synthesis | Z3 unsat | Log, skip this token |
| C3 Validation | py-evm error | Mark unvalidated, include in report |

---

## Performance Targets (per contract)

| Mode | Target Time | Notes |
|---|---|---|
| Concolic (active) | < 100s | 90% of contracts from paper dataset |
| Symbolic fallback | < 600s | Hard timeout |
| Deobfuscation only | < 10s | Branch table usually < 1000 entries |
| Validation per exploit | < 30s | Single fork execution |
