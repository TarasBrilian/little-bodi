# BYTECODE_ANALYSIS_ENGINE.md

## Responsibilities

Converts raw EVM bytecode into analyzable structures: instruction list, CFG, and indirect jump identification. This is the first engine in the pipeline and serves as the foundation for all subsequent analyses.

---

## Input / Output

```python
@dataclass
class BytecodeAnalysisInput:
    bytecode: bytes                    # raw EVM bytecode
    contract_address: Optional[str]   # for metadata only

@dataclass
class BytecodeAnalysisOutput:
    instructions: list[Instruction]
    jumpdests: set[int]               # valid JUMPDEST PCs
    push_data_ranges: list[tuple[int, int]]  # (start, end) ranges
    cfg: ControlFlowGraph
    indirect_jumps: list[IndirectJump]
    coverage_before: float            # % reachable blocks
    is_obfuscated: bool
```

---

## Main Algorithms

### PUSH-data aware Disassembly

```python
def disassemble(bytecode: bytes) -> tuple[list[Instruction], set[int]]:
    """
    Correct EVM disassembly: skip PUSH operands when scanning for JUMPDEST.
    
    This is critical because bytecode may contain 0x5B (JUMPDEST value)
    inside PUSH data, which is not a valid JUMPDEST.
    """
    instructions: list[Instruction] = []
    jumpdests: set[int] = set()
    push_data_ranges: list[tuple[int, int]] = []
    
    i = 0
    while i < len(bytecode):
        pc = i
        opcode = bytecode[i]
        
        # PUSH1 (0x60) to PUSH32 (0x7F)
        if 0x60 <= opcode <= 0x7F:
            push_size = opcode - 0x5F  # PUSH1=1, PUSH2=2, ..., PUSH32=32
            operand_start = i + 1
            operand_end = min(i + 1 + push_size, len(bytecode))
            operand = bytecode[operand_start:operand_end]
            
            push_data_ranges.append((operand_start, operand_end))
            instructions.append(Instruction(
                pc=pc,
                opcode=opcode,
                mnemonic=f"PUSH{push_size}",
                operand=operand,
                size=1 + len(operand)
            ))
            i = operand_end
            
        elif opcode == 0x5B:  # JUMPDEST
            jumpdests.add(pc)
            instructions.append(Instruction(
                pc=pc, opcode=opcode, mnemonic="JUMPDEST",
                operand=None, size=1
            ))
            i += 1
            
        else:
            mnemonic = OPCODE_TABLE.get(opcode, f"UNKNOWN_0x{opcode:02X}")
            instructions.append(Instruction(
                pc=pc, opcode=opcode, mnemonic=mnemonic,
                operand=None, size=1
            ))
            i += 1
    
    return instructions, jumpdests, push_data_ranges
```

---

### CFG Construction

```python
TERMINATORS = {
    0x00: "STOP",
    0x56: "JUMP",
    0xF3: "RETURN",
    0xFD: "REVERT",
    0xFE: "INVALID",
    0xFF: "SELFDESTRUCT",
}

CONDITIONAL_JUMP = 0x57  # JUMPI

def build_cfg(instructions: list[Instruction]) -> ControlFlowGraph:
    """
    Split instructions into basic blocks and determine edges.
    """
    blocks: dict[int, BasicBlock] = {}
    
    # Pass 1: Determine block boundaries
    block_starts: set[int] = {instructions[0].pc}
    for instr in instructions:
        if instr.opcode in TERMINATORS or instr.opcode == CONDITIONAL_JUMP:
            # Instruction after this starts a new block
            next_pc = _next_pc(instr, instructions)
            if next_pc is not None:
                block_starts.add(next_pc)
        if instr.opcode == 0x5B:  # JUMPDEST
            block_starts.add(instr.pc)
    
    # Pass 2: Group instructions into blocks
    # Pass 3: Determine edges
    # - JUMP: edge to top-of-stack (static or indirect)
    # - JUMPI: two edges (fall-through + taken)
    # - STOP/RETURN/REVERT: terminal
    # - Others: fall-through to next block
    
    return ControlFlowGraph(blocks=blocks, ...)
```

---

### Indirect Jump Detection

```python
def identify_indirect_jumps(
    cfg: ControlFlowGraph,
    instructions: list[Instruction]
) -> list[IndirectJump]:
    """
    Jump/JUMPI is considered indirect if the destination value
    originates from input data (calldata, memory, storage),
    rather than a PUSH constant.
    
    Implementation: backward slicing from top-of-stack at JUMP.
    """
    indirect = []
    
    for block in cfg.blocks.values():
        last_instr = block.instructions[-1]
        
        if last_instr.opcode not in (0x56, 0x57):  # JUMP, JUMPI
            continue
        
        # Backward slice: find where top-of-stack originates
        stack_source = _backward_slice_top_of_stack(
            last_instr.pc, cfg, instructions
        )
        
        # If not a PUSH constant → indirect
        if stack_source.source_type != StackSourceType.PUSH_CONSTANT:
            indirect.append(IndirectJump(
                pc=last_instr.pc,
                opcode=last_instr.opcode,
                stack_var=stack_source.var_name,
                depends_on=stack_source.input_dependencies  # e.g., ["calldata"]
            ))
    
    return indirect
```

---

### Reachability Analysis (Coverage)

```python
def compute_coverage(cfg: ControlFlowGraph) -> float:
    """
    BFS from entry points to determine reachable blocks.
    Entry points = blocks starting at PC=0 or JUMPDESTs
    reachable from PC=0.
    """
    visited: set[int] = set()
    queue = deque([0])  # PC=0 is always an entry
    
    while queue:
        pc = queue.popleft()
        if pc in visited or pc not in cfg.blocks:
            continue
        visited.add(pc)
        block = cfg.blocks[pc]
        for succ_pc in block.successors:
            if succ_pc not in visited:
                queue.append(succ_pc)
    
    reachable = len(visited)
    total = len(cfg.blocks)
    return reachable / total if total > 0 else 0.0
```

---

## Opcode Reference Table (Partial)

```python
OPCODE_TABLE: dict[int, str] = {
    0x00: "STOP",
    0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x04: "DIV",
    0x10: "LT", 0x11: "GT", 0x12: "SLT", 0x13: "SGT", 0x14: "EQ",
    0x16: "AND", 0x17: "OR", 0x18: "XOR", 0x19: "NOT",
    0x1A: "BYTE", 0x1B: "SHL", 0x1C: "SHR", 0x1D: "SAR",
    0x20: "KECCAK256",
    0x30: "ADDRESS", 0x31: "BALANCE", 0x32: "ORIGIN", 0x33: "CALLER",
    0x34: "CALLVALUE", 0x35: "CALLDATALOAD", 0x36: "CALLDATASIZE",
    0x37: "CALLDATACOPY",
    0x50: "POP", 0x51: "MLOAD", 0x52: "MSTORE", 0x53: "MSTORE8",
    0x54: "SLOAD", 0x55: "SSTORE",
    0x56: "JUMP", 0x57: "JUMPI", 0x58: "PC", 0x5B: "JUMPDEST",
    0xF1: "CALL", 0xF2: "CALLCODE", 0xF4: "DELEGATECALL",
    0xF3: "RETURN", 0xFA: "STATICCALL", 0xFD: "REVERT",
    0xFE: "INVALID", 0xFF: "SELFDESTRUCT",
    # DUP1-DUP16: 0x80-0x8F
    # SWAP1-SWAP16: 0x90-0x9F
    # PUSH1-PUSH32: 0x60-0x7F
}
```

---

## Error Handling

```python
class BytecodeAnalysisError(Exception): pass
class InvalidBytecodeError(BytecodeAnalysisError): pass
class CFGConstructionError(BytecodeAnalysisError): pass
class BytecodeTooLargeError(BytecodeAnalysisError): pass

MAX_BYTECODE_SIZE = 24576  # EIP-170: 24KB limit

def validate_bytecode(bytecode: bytes) -> None:
    if len(bytecode) == 0:
        raise InvalidBytecodeError("Empty bytecode")
    if len(bytecode) > MAX_BYTECODE_SIZE:
        raise BytecodeTooLargeError(
            f"Bytecode size {len(bytecode)} exceeds EVM limit {MAX_BYTECODE_SIZE}"
        )
```

---

## Test Cases

```python
# tests/unit/test_bytecode_analysis.py

def test_jumpdest_in_push_data_not_counted():
    """
    Byte 0x5B inside PUSH data is not a valid JUMPDEST.
    PUSH1 0x5B → operand 0x5B is not a JUMPDEST.
    """
    bytecode = bytes.fromhex("60" + "5B")  # PUSH1 0x5B
    engine = BytecodeAnalysisEngine()
    result = engine.run(bytecode)
    assert 1 not in result.jumpdests  # PC=1 is not a valid JUMPDEST


def test_indirect_jump_detection():
    """
    JUMP with destination from CALLDATALOAD must be detected as indirect.
    """
    # CALLDATALOAD(0) → SHR 0xf0 → JUMP
    bytecode = bytes.fromhex("6000" + "35" + "60f0" + "1c" + "56")
    engine = BytecodeAnalysisEngine()
    result = engine.run(bytecode)
    assert len(result.indirect_jumps) == 1
    assert result.indirect_jumps[0].depends_on == ["calldata"]

def test_obfuscated_contract_low_coverage():
    """Contracts with indirect jumps must have low coverage before deobfuscation."""
    ...
```
