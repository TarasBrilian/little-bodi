# SYMBOLIC_EXECUTION_ENGINE.md

## Tanggung Jawab

Mengeksplorasi execution paths kontrak dengan memperlakukan input (calldata, caller, origin) sebagai symbolic variables. Digunakan sebagai fallback ketika concolic execution gagal atau tidak ada historical transactions.

---

## Input / Output

```python
@dataclass
class SymbolicExecutionInput:
    deobfuscated_cfg: ControlFlowGraph
    deobfuscated_bytecode: bytes
    target_call_pcs: Optional[list[int]]  # jika None, explore semua
    config: SymbolicConfig

@dataclass
class SymbolicConfig:
    max_paths: int = 10_000
    max_depth: int = 500
    timeout_seconds: int = 600
    branch_table_max_visits: int = 2
    adversary_address: str = "0xDeadDeAddeAddEAddeadDEaDDEAdDeaDDeAD0000"
    
@dataclass
class SymbolicExecutionOutput:
    execution_traces: list[ExecutionTrace]
    paths_explored: int
    paths_pruned: int
    timeout_reached: bool
```

---

## State Model

### SymbolicState

```python
@dataclass
class SymbolicState:
    pc: int
    stack: list[z3.BitVecRef | int]      # mix of symbolic dan concrete
    memory: dict[int, z3.BitVecRef | int]
    storage: dict[int, z3.BitVecRef | int]
    path_constraints: list[z3.BoolRef]
    taint_map: TaintMap                   # tracking taint per value
    call_depth: int
    branch_table_visits: int             # untuk pruning rule
    
    # Transaction context
    calldata: z3.BitVecRef               # symbolic calldata
    caller: z3.BitVecRef | int           # bisa concrete (adversary addr) atau symbolic
    origin: z3.BitVecRef | int
    value: z3.BitVecRef | int
    
    # Trace accumulation
    calls_encountered: list[CallEncounter]
    
    def is_feasible(self) -> bool:
        """Check apakah path constraints satisfiable via Z3."""
        solver = z3.Solver()
        solver.add(*self.path_constraints)
        return solver.check() == z3.sat
    
    def fork(self, new_constraint: z3.BoolRef) -> 'SymbolicState':
        """Buat copy state dengan constraint tambahan."""
        new_state = copy.deepcopy(self)
        new_state.path_constraints.append(new_constraint)
        return new_state
```

### CallEncounter

```python
@dataclass
class CallEncounter:
    pc: int
    gas: StackValue
    target_address: StackValue
    value: StackValue
    args_offset: StackValue
    args_size: StackValue
    
    # Decoded dari memory jika bisa
    function_selector: Optional[bytes | z3.BitVecRef]
    arg1_recipient: Optional[z3.BitVecRef]  # 32 bytes
    arg2_amount: Optional[z3.BitVecRef]     # 32 bytes
    
    # Taint info
    taint: CallTaintInfo
```

---

## Symbolic EVM Interpreter

### Core Execution Loop

```python
class SymbolicEVMInterpreter:
    def __init__(self, bytecode: bytes, cfg: ControlFlowGraph, config: SymbolicConfig):
        self.bytecode = bytecode
        self.cfg = cfg
        self.config = config
        self.solver = z3.Solver()
    
    def execute(self, initial_state: SymbolicState) -> list[ExecutionTrace]:
        """
        DFS execution dengan state forking di setiap conditional branch.
        """
        traces = []
        worklist: list[SymbolicState] = [initial_state]
        paths_explored = 0
        start_time = time.time()
        
        while worklist and paths_explored < self.config.max_paths:
            if time.time() - start_time > self.config.timeout_seconds:
                logger.warning("Symbolic execution timeout reached")
                break
            
            state = worklist.pop()  # DFS: pop dari belakang
            
            if state.pc not in self.cfg.blocks:
                continue
            
            result = self._execute_block(state)
            
            match result.type:
                case "terminal":
                    traces.append(ExecutionTrace.from_state(state))
                    paths_explored += 1
                
                case "fork":
                    # JUMPI: fork ke dua paths
                    taken_state, fallthrough_state = result.states
                    
                    # Prune infeasible paths
                    if taken_state.is_feasible():
                        worklist.append(taken_state)
                    if fallthrough_state.is_feasible():
                        worklist.append(fallthrough_state)
                
                case "continue":
                    worklist.append(result.state)
                
                case "prune":
                    logger.debug(f"Path pruned at PC={state.pc}: {result.reason}")
        
        return traces
```

### Opcode Handlers (Key Operations)

```python
def handle_CALLDATALOAD(state: SymbolicState, instr: Instruction) -> SymbolicState:
    """
    CALLDATALOAD: pop offset, push 32 bytes dari calldata sebagai symbolic value.
    """
    offset = state.stack.pop()
    
    if isinstance(offset, int):
        # Concrete offset → symbolic slice dari calldata
        sym_value = z3.Extract(
            (offset + 32) * 8 - 1,
            offset * 8,
            state.calldata
        )
        # Taint: nilai ini tainted karena dari calldata
        state.taint_map.mark_tainted(sym_value, source="calldata", offset=offset)
    else:
        # Symbolic offset → fully symbolic value
        sym_value = z3.BitVec(f"calldata_at_symbolic_offset_{state.pc}", 256)
        state.taint_map.mark_tainted(sym_value, source="calldata_dynamic")
    
    state.stack.append(sym_value)
    return state

def handle_JUMP(state: SymbolicState, instr: Instruction) -> ExecutionResult:
    """
    JUMP: pop destination.
    - Jika concrete dan valid JUMPDEST → continue ke destination
    - Jika symbolic → harusnya sudah di-handle oleh deobfuscation (branch table)
    """
    destination = state.stack.pop()
    
    if isinstance(destination, int):
        if destination in valid_jumpdests:
            new_state = state.copy()
            new_state.pc = destination
            return ExecutionResult.continue_(new_state)
        else:
            return ExecutionResult.prune("Invalid jump destination")
    else:
        # Symbolic destination setelah deobfuscation seharusnya tidak terjadi
        # Jika terjadi, log dan prune
        logger.warning(f"Symbolic JUMP destination at PC={instr.pc} after deobfuscation")
        return ExecutionResult.prune("Symbolic jump after deobfuscation (unexpected)")

def handle_JUMPI(state: SymbolicState, instr: Instruction) -> ExecutionResult:
    """
    JUMPI: pop destination dan condition.
    Fork menjadi dua paths.
    """
    destination = state.stack.pop()
    condition = state.stack.pop()
    
    # Path 1: taken (condition != 0)
    taken = state.fork(condition != 0)
    taken.pc = destination if isinstance(destination, int) else None
    
    # Path 2: fall-through (condition == 0)
    fallthrough = state.fork(condition == 0)
    fallthrough.pc = instr.pc + 1
    
    # Branch table visit counting (pruning rule dari paper)
    if destination == BRANCH_TABLE_OFFSET:
        taken.branch_table_visits += 1
        if taken.branch_table_visits > state.config.branch_table_max_visits:
            return ExecutionResult.prune_one(fallthrough, "Branch table visit limit")
    
    return ExecutionResult.fork(taken, fallthrough)

def handle_CALL(state: SymbolicState, instr: Instruction) -> SymbolicState:
    """
    CALL: record encounter, lalu continue (kita tidak masuk ke called contract).
    """
    gas = state.stack.pop()
    target = state.stack.pop()
    value = state.stack.pop()
    args_offset = state.stack.pop()
    args_size = state.stack.pop()
    ret_offset = state.stack.pop()
    ret_size = state.stack.pop()
    
    # Decode calldata dari memory
    selector, arg1, arg2 = decode_call_args(state.memory, args_offset, args_size)
    
    encounter = CallEncounter(
        pc=instr.pc,
        gas=gas, target_address=target, value=value,
        args_offset=args_offset, args_size=args_size,
        function_selector=selector,
        arg1_recipient=arg1,
        arg2_amount=arg2,
        taint=extract_call_taint(state.taint_map, target, selector, arg1, arg2)
    )
    
    state.calls_encountered.append(encounter)
    
    # Push symbolic return value (success/failure tidak diketahui)
    state.stack.append(z3.BitVec(f"call_result_{instr.pc}", 256))
    
    return state
```

---

## Taint Map Implementation

```python
class TaintMap:
    """
    Track taint dari calldata ke values di stack/memory/storage.
    Granularity: per Z3 variable reference.
    """
    def __init__(self):
        self._tainted: dict[str, TaintInfo] = {}  # var_id -> info
    
    def mark_tainted(self, value: z3.BitVecRef, source: str, offset: Optional[int] = None):
        var_id = str(value)
        self._tainted[var_id] = TaintInfo(source=source, calldata_offset=offset)
    
    def is_tainted(self, value: z3.BitVecRef | int) -> bool:
        if isinstance(value, int):
            return False
        # Check if any sub-expression is tainted
        return self._check_tainted_recursive(value)
    
    def _check_tainted_recursive(self, expr: z3.ExprRef) -> bool:
        """Conservative: jika ada sub-expr tainted, seluruh expr tainted."""
        if str(expr) in self._tainted:
            return True
        for child in expr.children():
            if self._check_tainted_recursive(child):
                return True
        return False
    
    def get_tainted_calldata_bytes(self, value: z3.BitVecRef) -> list[int]:
        """Return calldata byte offsets yang mempengaruhi value ini."""
        ...
```

---

## Z3 Word Size Management

Semua EVM values adalah 256-bit integers:

```python
EVM_WORD_BITS = 256

def new_symbolic_word(name: str) -> z3.BitVecRef:
    return z3.BitVec(name, EVM_WORD_BITS)

def concrete_to_symbolic(value: int) -> z3.BitVecRef:
    return z3.BitVecVal(value, EVM_WORD_BITS)

def address_to_symbolic(addr: str) -> z3.BitVecRef:
    """Convert Ethereum address ke Z3 BitVec (mengambil 20 bytes = 160 bits, zero-padded ke 256)."""
    addr_int = int(addr, 16)
    return z3.BitVecVal(addr_int, EVM_WORD_BITS)
```

---

## Path Pruning Strategies

1. **Unsatisfiable constraints**: jalankan Z3 solver, prune jika unsat
2. **Branch table visit limit**: maksimum 2 kunjungan ke branch table per path
3. **CFG lookahead**: jika path constraint tidak bisa reach target CALL → prune
4. **Depth limit**: prune jika call depth > max_depth
5. **Visited state deduplication**: prune jika (PC, constraints hash) sudah pernah dikunjungi

---

## Test Cases

```python
def test_symbolic_calldata_propagation():
    """
    CALLDATALOAD harus menghasilkan symbolic value.
    Operasi aritmetika pada symbolic value tetap symbolic.
    """
    ...

def test_path_fork_at_jumpi():
    """
    JUMPI harus menghasilkan dua state dengan constraints yang berlawanan.
    """
    ...

def test_taint_propagation_through_add():
    """
    ADD(tainted, concrete) harus menghasilkan tainted.
    """
    ...

def test_z3_unsat_pruning():
    """
    Path dengan constraints yang kontradiktif harus di-prune.
    """
    ...
```
