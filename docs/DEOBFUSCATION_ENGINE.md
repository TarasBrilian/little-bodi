# DEOBFUSCATION_ENGINE.md

## Responsibilities

Takes bytecode with indirect jumps and generates a fully explicit CFG representation with all jump destinations as direct jumps. This engine implements the "branch table injection" technique from the SKANF paper.

---

## Input / Output

```python
@dataclass
class DeobfuscationInput:
    bytecode: bytes
    cfg: ControlFlowGraph
    indirect_jumps: list[IndirectJump]
    jumpdests: set[int]

@dataclass
class DeobfuscationOutput:
    deobfuscated_cfg: ControlFlowGraph  # CFG with all direct jumps
    instrumented_bytecode: bytes        # bytecode with branch table (for execution)
    branch_table_entries: list[int]     # all JUMPDESTs inserted into table
    branch_table_size: int              # number of entries
    coverage_after: float
```

---

## Branch Table Concept

Instead of modifying bytecode in-place (which changes PC offsets), Little Bodi:
1. Modifies the CFG representation for analysis
2. Injects a branch table at the end of the bytecode (offset 0xe000) for execution

```
Original indirect jump at PC 0x0059:
  SHR          ; v58 = calldata >> 0xf0
  JUMP         ; jump to v58 (unknown statically)

After deobfuscation (at CFG level):
  SHR          ; v58 still exists
  PUSH 0xe000  ; redirect to branch table
  JUMP         ; jump to branch table

Branch table at 0xe000:
  JUMPDEST
  DUP1              ; copy v58
  PUSH2 0x0a00      ; try destination 0x0a00
  EQ
  PUSH2 0xf000      ; intermediate for 0x0a00
  JUMPI
  DUP1              ; copy v58 again
  PUSH2 0x0b00      ; try destination 0x0b00
  ...

Intermediate for each destination:
  [0xf000] JUMPDEST
  [0xf001] POP       ; remove v58 copy
  [0xf002] PUSH2 0x0a00
  [0xf005] JUMP      ; actual jump to 0x0a00
```

---

## Algorithm

### Step 1: Collect All Valid Destinations

```python
def collect_all_destinations(jumpdests: set[int]) -> list[int]:
    """
    All JUMPDESTs in the bytecode are candidate destinations.
    Order: ascending by PC for determinism.
    """
    return sorted(jumpdests)
```

### Step 2: Build Branch Table Bytecode

```python
BRANCH_TABLE_OFFSET = 0xe000
INTERMEDIATE_OFFSET = 0xf000

def build_branch_table(destinations: list[int]) -> bytes:
    """
    Generates bytecode for a branch table that performs a lookup
    of the value on top-of-stack against all valid destinations.
    
    Stack upon entering branch table: [destination_value]
    """
    table_code = bytearray()
    
    # Branch table entry point
    table_code += bytes([0x5B])  # JUMPDEST at 0xe000
    
    intermediate_pc = INTERMEDIATE_OFFSET
    
    for dest in destinations:
        # DUP1 — copy destination value
        table_code += bytes([0x80])
        
        # PUSH2 <dest> — push known destination
        table_code += bytes([0x61]) + dest.to_bytes(2, 'big')
        
        # EQ — compare
        table_code += bytes([0x14])
        
        # PUSH2 <intermediate_pc> — where to jump if match
        table_code += bytes([0x61]) + intermediate_pc.to_bytes(2, 'big')
        
        # JUMPI — conditional jump to intermediate
        table_code += bytes([0x57])
        
        intermediate_pc += 6  # each intermediate is 6 bytes
    
    # INVALID at the end of table (if no match)
    table_code += bytes([0xFE])
    
    return bytes(table_code)

def build_intermediates(destinations: list[int]) -> bytes:
    """
    Intermediate gadgets: one per destination.
    Function: POP copy, then JUMP to actual destination.
    """
    intermediates = bytearray()
    
    for dest in destinations:
        intermediates += bytes([0x5B])  # JUMPDEST
        intermediates += bytes([0x50])  # POP (remove copy from DUP1)
        intermediates += bytes([0x61]) + dest.to_bytes(2, 'big')  # PUSH2 <dest>
        intermediates += bytes([0x56])  # JUMP
    
    return bytes(intermediates)
```

### Step 3: Instrument Indirect Jump Locations

```python
def instrument_indirect_jumps(
    bytecode: bytes,
    indirect_jumps: list[IndirectJump]
) -> bytes:
    """
    For each indirect jump, inject PUSH 0xe000 before it.
    
    Since byte injection changes PC offsets, we operate at the CFG level
    rather than raw bytes. For execution, we build new bytecode.
    
    Special case JUMPI:
    - Before PUSH 0xe000: insert SWAP1 (preserve condition below destination)
    - After JUMPI fall-through: insert POP (cleanup destination from stack)
    """
    ...
```

### Step 4: Assemble Final Instrumented Bytecode

```python
def assemble_instrumented(
    original_bytecode: bytes,
    instrumented_jumps: dict[int, bytes],  # PC -> replacement bytes
    branch_table: bytes,
    intermediates: bytes,
) -> bytes:
    """
    Combine:
    1. Original bytecode with redirected indirect jumps
    2. Padding to 0xe000
    3. Branch table at 0xe000
    4. Intermediates at 0xf000
    
    Total size must not exceed the max bytecode size in our environment
    (for analysis, we can relax the 24KB limit as this is not deployment).
    """
    result = bytearray(original_bytecode)
    
    # Apply jump redirects (complex: requires PC offset management)
    # ...
    
    # Pad to 0xe000
    while len(result) < BRANCH_TABLE_OFFSET:
        result += bytes([0x00])  # STOP as padding
    
    # Insert branch table at 0xe000
    result[BRANCH_TABLE_OFFSET:BRANCH_TABLE_OFFSET + len(branch_table)] = branch_table
    
    # Insert intermediates at 0xf000
    result[INTERMEDIATE_OFFSET:INTERMEDIATE_OFFSET + len(intermediates)] = intermediates
    
    return bytes(result)
```

---

## CFG-Level Deobfuscation (for Analysis)

For analysis purposes (not execution), modifications are easier at the CFG level:

```python
def deobfuscate_cfg(
    cfg: ControlFlowGraph,
    indirect_jumps: list[IndirectJump],
    destinations: list[int]
) -> ControlFlowGraph:
    """
    For each indirect jump in CFG:
    - Remove the current "unknown" edge
    - Add edges to ALL valid destinations
    
    This is an over-approximation (false edges may exist),
    but better than under-approximation (missing edges).
    Over-approximation will be filtered by symbolic execution.
    """
    new_cfg = cfg.copy()
    
    for indirect_jump in indirect_jumps:
        block = new_cfg.find_block_containing(indirect_jump.pc)
        # Remove unknown successor
        block.successors = [s for s in block.successors if s is not None]
        # Add all valid destinations as successors
        for dest in destinations:
            if dest not in block.successors:
                block.successors.append(dest)
    
    return new_cfg
```

---

## JUMPI Special Handling

JUMPI has two stack values: `[condition, destination]` (condition below destination).

```
Stack before JUMPI:
  TOP: destination_value  ← indirect one
  BELOW: condition

After injecting SWAP1 + PUSH 0xe000:
  Stack before modification:
    TOP: destination_value
    BELOW: condition
  
  After SWAP1:
    TOP: condition
    BELOW: destination_value
  
  After PUSH 0xe000:
    TOP: 0xe000         ← destination for JUMPI
    BELOW: condition    ← evaluated by JUMPI
    BOTTOM: destination_value  ← still exists, cleaned later
  
  JUMPI uses TOP (0xe000) and 2nd (condition):
    - If condition != 0: jump to 0xe000
    - If condition == 0: fall-through
  
  POP after fall-through cleans destination_value from stack.
```

---

## Constraints and Edge Cases

### Size Constraint
```python
def validate_branch_table_fits(destinations: list[int]) -> bool:
    """
    Branch table: (8 bytes * len(destinations)) + 1 (JUMPDEST) + 1 (INVALID)
    Intermediates: 6 bytes * len(destinations)
    
    Total must fit between 0xe000 and 0xFFFF (8192 bytes available).
    """
    table_size = 1 + (8 * len(destinations)) + 1
    intermediate_size = 6 * len(destinations)
    total = table_size + intermediate_size
    
    available = 0xFFFF - 0xe000  # 8191 bytes
    return total <= available

# With 1000 destinations:
# table: 1 + 8000 + 1 = 8002 bytes
# intermediates: 6000 bytes
# total: 14002 > 8191 → does not fit in one region
# Solution: extend beyond 0x10000+ (for analysis tools, no hard 24KB limit)
```

### Destination Pruning for Efficiency
If there are too many destinations, prioritize JUMPDESTs reachable from the initial analysis.

---

## Metrics

```python
@dataclass
class DeobfuscationMetrics:
    original_indirect_jump_count: int
    branch_table_entry_count: int
    coverage_before: float
    coverage_after: float
    deobfuscation_successful: bool
    
    @property
    def improvement(self) -> float:
        return self.coverage_after - self.coverage_before
```

---

## Test Cases

```python
def test_simple_indirect_jump_deobfuscation():
    """
    Simple contract with one indirect jump.
    After deobfuscation, all JUMPDESTs must be reachable.
    """
    ...

def test_jumpi_special_handling():
    """
    JUMPI with indirect destination:
    - SWAP1 inserted before PUSH 0xe000
    - POP inserted in fall-through path
    - Stack balance must be maintained
    """
    ...

def test_jumpdest_in_push_not_in_table():
    """
    PUSH byte 0x5B must not enter the branch table.
    """
    bytecode = bytes.fromhex("605B" + "5B" + "56")  # PUSH1 0x5B, JUMPDEST, JUMP
    # Only PC=2 is a valid JUMPDEST, not PC=1
    ...
```
