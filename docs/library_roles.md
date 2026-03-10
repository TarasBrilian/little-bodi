# library_roles.md — Specific Roles for Each Library

This is a critical document to avoid confusion between libraries with similar functions.
Read this before starting the implementation of any engine.

---

## py-evm vs pyevmasm — Fundamental Differences

### pyevmasm
**Use for**: Disassembly (bytecode → instruction list)

```python
import evmasm

# Input: raw bytes
# Output: list of EVMAsm objects with .pc, .name, .operand
instructions = evmasm.disassemble_all(bytecode)

for instr in instructions:
    print(f"PC={instr.pc} | {instr.name} | operand={instr.operand}")
```

**ONLY for**: reading bytecode, not running it.
`pyevmasm` does not execute bytecode. It is a pure disassembler.

---

### py-evm (eth package)
**Use for**: Running bytecode in a real EVM (execution, fork state)

```python
from eth.chains.mainnet import MainnetChain
from eth.db.atomic import AtomicDB
from eth.vm.forks.cancun import CancunVM  # or appropriate fork
```

**ONLY for**: ValidationEngine and LocalEVMFork. Do not use in other engines.
**Do not use py-evm for disassembly** — that is not its function.

---

## z3-solver
**Use for**: Constraint solving (SymbolicEngine, ExploitGenerationEngine)

```python
import z3

# Create symbolic variable
x = z3.BitVec("calldata_byte_0", 256)

# Add constraint
s = z3.Solver()
s.add(x == 0xa9059cbb)

# Solve
if s.check() == z3.sat:
    model = s.model()
    value = model[x].as_long()
```

**Do not use** for actual EVM execution — only for constraint solving.
**Always use BitVec(n, 256)** for EVM values, not `Int()` or `Real()`.

---

## web3.py
**Use for**: Interaction with live/archive Ethereum nodes via RPC

```python
from web3 import Web3

w3 = Web3(Web3.HTTPProvider(rpc_url))

# Fetch bytecode
code = w3.eth.get_code(address, block_identifier=block_number)

# Fetch transaction
tx = w3.eth.get_transaction(tx_hash)

# Call contract (without state change)
result = w3.eth.call({"to": token_addr, "data": calldata}, block_number)

# Get logs
logs = w3.eth.get_logs({...})
```

**Use in**: SeedExtractor, TokenDiscovery, ValidationEngine (for loading state)
**DO NOT** use for executing exploit transactions (use py-evm local fork)

---

## networkx
**Use for**: CFG representation and graph algorithms

```python
import networkx as nx

# CFG as a directed graph
cfg = nx.DiGraph()
cfg.add_node(0, block=BasicBlock(...))
cfg.add_edge(0, 8)  # edge from PC=0 to PC=8

# Reachability
reachable = nx.descendants(cfg, 0)  # all nodes reachable from PC=0
reachable.add(0)

# Path finding
paths = list(nx.all_simple_paths(cfg, source=0, target=call_pc, cutoff=50))
```

**Use in**: BytecodeAnalysisEngine (CFG), VulnerabilityEngine (reachability check)

---

## pydantic
**Use for**: Data model validation and serialization

```python
from pydantic import BaseModel, field_validator

class VulnCallParam(BaseModel):
    is_adversary_controllable: bool
    is_risky_fixed: bool
    tainted_bytes: list[int] = []

class PotentialVulnerability(BaseModel):
    call_pc: int
    target_address: VulnCallParam
    # ...
    
    @field_validator("call_pc")
    def call_pc_must_be_positive(cls, v):
        if v < 0:
            raise ValueError("PC cannot be negative")
        return v

# Serialize to JSON
vuln = PotentialVulnerability(...)
json_str = vuln.model_dump_json()

# Deserialize from JSON
vuln2 = PotentialVulnerability.model_validate_json(json_str)
```

**Use in**: all data models (PotentialVulnerability, Exploit, ValidatedExploit, Report)
**DO NOT** use `@dataclass` for models that need JSON serialization — use Pydantic.

---

## rich
**Use for**: Readable CLI output

```python
from rich.console import Console
from rich.table import Table
from rich import print as rprint

console = Console()
console.print("[bold green]Analysis complete[/]")
console.print_json(json_str)  # pretty-print JSON

# Progress bar for batch mode
from rich.progress import track
for contract in track(contracts, description="Analyzing..."):
    ...
```

**Use in**: scripts/analyze.py, ReportingEngine (CLI summary)
**DO NOT** import rich in engine files — only in scripts/ and reporting/

---

## Summary: Which Library for Which Task?

| Task | Library |
|---|---|
| Bytecode → instruction list | `pyevmasm` |
| CFG construction | `networkx` + custom logic |
| Symbolic variable + constraint | `z3-solver` |
| Execute transaction locally | `py-evm` |
| Query archive node / RPC | `web3.py` |
| Data models + JSON | `pydantic` |
| CLI output | `rich` + `click` |
| Graph reachability | `networkx` |
| Async HTTP (seed fetching) | `aiohttp` |

---

## What DOES NOT Have a Library (must be custom)

The following must be implemented manually because no off-the-shelf library exists:

1. **TaintMap** — no Python library for EVM byte-level taint tracking.
2. **Branch Table Injection** — custom bytecode transformation logic.
3. **Indirect Jump Detection** — custom backward slicing in the CFG.
4. **Concolic Dual-Track State** — custom ConcreteSymbolicState.
5. **Vulnerability Oracle** — custom classification logic based on the paper.

All of these are in the `core/` directory, and their specifications are in the respective ENGINE.md files.

---

## Common Gotchas

### py-evm version compatibility
py-evm is still in beta (`0.10.0b4`). The API can change. Always wrap it in the `LocalEVMFork` class so that if the API changes, the update is only in one place.

### pyevmasm JUMPDEST false positives
`evmasm.disassemble_all()` by default **does not** skip PUSH data when scanning for JUMPDESTs. You must implement a custom `collect_jumpdests()` as described in `BYTECODE_ANALYSIS_ENGINE.md` to get correct results.

### z3 BitVec overflow
EVM uses modular arithmetic (mod 2^256). Z3 BitVec automatically handles this because it is fixed-width. However, when converting from Python int to Z3:
```python
# Correct
z3.BitVecVal(2**256 - 1, 256)  # max uint256

# Incorrect — integer too large for naive Python int → Z3 conversion
z3.IntVal(2**256 - 1)  # this is Z3 Int, not BitVec
```

### web3.py checksum addresses
web3.py is strict about checksum addresses. Always use:
```python
from web3 import Web3
addr = Web3.to_checksum_address("0xdead...beef")
```

### py-evm fork state loading
Loading the full state from an archive node for py-evm can be slow. Cache the state in `data/seeds/` using the block number as the key.
