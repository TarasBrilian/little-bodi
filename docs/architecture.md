# architecture.md — Desain Arsitektur Little Bodi

## Gambaran Umum

Little Bodi menggunakan arsitektur **pipeline dengan shared context**. Setiap engine membaca dari dan menulis ke objek `AnalysisContext` yang dilewatkan sepanjang pipeline. Tidak ada database runtime — semua state ada di memori selama analisis, lalu diserialisasi ke JSON/file di akhir.

---

## Diagram Arsitektur

```
┌─────────────────────────────────────────────────────────────┐
│                    CLI / API Entry Point                     │
│                     scripts/analyze.py                      │
└──────────────────────────┬──────────────────────────────────┘
                           │
                    AnalysisContext
                           │
           ┌───────────────▼────────────────┐
           │        Pipeline Orchestrator    │
           │        core/pipeline.py         │
           └───────────────┬────────────────┘
                           │
          ┌────────────────┼─────────────────────────┐
          │                │                         │
          ▼                ▼                         ▼
   ┌─────────────┐  ┌─────────────┐         ┌──────────────┐
   │  STAGE A    │  │  STAGE B    │         │   STAGE C    │
   │             │  │             │         │              │
   │ Bytecode    │→ │ Vulnerability│→       │ Exploit Gen  │
   │ Analysis    │  │ Detection   │         │ & Validation │
   │             │  │             │         │              │
   └──────┬──────┘  └──────┬──────┘         └──────┬───────┘
          │                │                        │
   ┌──────▼──────┐  ┌──────▼──────┐         ┌──────▼───────┐
   │ Deobfus-    │  │ Symbolic /  │         │ Validation   │
   │ cation      │  │ Concolic    │         │ Engine       │
   │ Engine      │  │ Engine      │         └──────┬───────┘
   └─────────────┘  └─────────────┘                │
                           │                        ▼
                    ┌──────▼──────┐         ┌──────────────┐
                    │ Vulnerability│         │ Reporting    │
                    │ Engine      │         │ Engine       │
                    └─────────────┘         └──────────────┘
```

---

## Komponen Inti

### AnalysisContext
Object pusat yang dibawa sepanjang pipeline:

```python
@dataclass
class AnalysisContext:
    # Input
    bytecode: bytes
    contract_address: Optional[str]
    chain_id: int
    block_number: Optional[int]
    
    # Stage A outputs
    disassembly: Optional[DisassemblyResult]
    cfg: Optional[ControlFlowGraph]
    indirect_jumps: list[IndirectJump]
    deobfuscated_bytecode: Optional[bytes]
    deobfuscated_cfg: Optional[ControlFlowGraph]
    coverage_before: float
    coverage_after: float
    
    # Stage B outputs
    seed_inputs: list[SeedInput]
    execution_traces: list[ExecutionTrace]
    potential_vulnerabilities: list[PotentialVulnerability]
    
    # Stage C outputs
    exploits: list[Exploit]
    validated_exploits: list[ValidatedExploit]
    
    # Metadata
    analysis_start: datetime
    analysis_end: Optional[datetime]
    errors: list[AnalysisError]
    config: AnalysisConfig
```

---

## Engine Interfaces

```python
from abc import ABC, abstractmethod

class BaseEngine(ABC):
    def __init__(self, config: AnalysisConfig) -> None:
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
    
    @abstractmethod
    def run(self, ctx: AnalysisContext) -> AnalysisContext:
        """Mutate dan return context dengan hasil engine."""
        pass
    
    @abstractmethod
    def validate_input(self, ctx: AnalysisContext) -> None:
        """Raise EngineInputError jika context tidak valid."""
        pass
    
    def execute(self, ctx: AnalysisContext) -> AnalysisContext:
        """Template method — jangan override ini."""
        self.validate_input(ctx)
        start = time.perf_counter()
        result = self.run(ctx)
        elapsed = time.perf_counter() - start
        self.logger.info(f"{self.__class__.__name__} completed in {elapsed:.2f}s")
        return result
```

---

## Data Models Utama

### DisassemblyResult
```python
@dataclass
class Instruction:
    pc: int
    opcode: int
    mnemonic: str
    operand: Optional[bytes]  # untuk PUSH instructions
    size: int  # bytes

@dataclass
class DisassemblyResult:
    instructions: list[Instruction]
    jumpdests: set[int]
    push_data_ranges: list[tuple[int, int]]  # untuk filter JUMPDEST palsu
```

### ControlFlowGraph
```python
@dataclass
class BasicBlock:
    start_pc: int
    end_pc: int
    instructions: list[Instruction]
    successors: list[int]  # PC dari block berikutnya
    predecessors: list[int]
    is_reachable: bool

@dataclass
class ControlFlowGraph:
    blocks: dict[int, BasicBlock]  # keyed by start_pc
    entry_points: list[int]
    indirect_jumps: list[int]  # PCs dari indirect jumps
```

### IndirectJump
```python
@dataclass
class IndirectJump:
    pc: int
    opcode: int  # JUMP (0x56) atau JUMPI (0x57)
    stack_var: str  # symbolic name dari destination variable
    depends_on: list[str]  # calldata, storage, memory
```

### PotentialVulnerability
```python
@dataclass
class VulnCallParam:
    is_adversary_controllable: bool
    is_risky_fixed: bool  # e.g., fixed ERC-20 address atau transfer selector
    tainted_bytes: list[int]  # calldata byte indices

@dataclass
class PotentialVulnerability:
    call_pc: int
    target_address: VulnCallParam
    function_selector: VulnCallParam
    recipient_arg: VulnCallParam
    amount_arg: VulnCallParam
    requires_tx_origin_control: bool
    path_constraints: list  # Z3 expressions
    seed_calldata: bytes  # concrete calldata yang memicu CALL ini
```

### Exploit
```python
@dataclass
class Exploit:
    vuln: PotentialVulnerability
    from_address: str
    to_address: str  # victim contract
    calldata: bytes
    value: int
    block_number: int
    target_token: str  # ERC-20 address
    expected_transfer_amount: int
```

### ValidatedExploit
```python
@dataclass
class ValidatedExploit:
    exploit: Exploit
    success: bool
    tx_receipt: Optional[dict]
    transfer_events: list[dict]
    estimated_loss_usd: float
    validation_error: Optional[str]
```

---

## Data Flow antar Engine

```
BytecodeAnalysisEngine
  writes: ctx.disassembly, ctx.cfg, ctx.indirect_jumps, ctx.coverage_before

DeobfuscationEngine
  reads:  ctx.bytecode, ctx.indirect_jumps, ctx.cfg
  writes: ctx.deobfuscated_bytecode, ctx.deobfuscated_cfg, ctx.coverage_after

SeedExtractionModule (bagian dari ConcolicEngine)
  reads:  ctx.contract_address, ctx.block_number (via RPC)
  writes: ctx.seed_inputs

ConcolicExecutionEngine / SymbolicExecutionEngine
  reads:  ctx.deobfuscated_bytecode, ctx.seed_inputs
  writes: ctx.execution_traces

VulnerabilityEngine
  reads:  ctx.execution_traces, ctx.deobfuscated_cfg
  writes: ctx.potential_vulnerabilities

ExploitGenerationEngine
  reads:  ctx.potential_vulnerabilities, ctx.contract_address (token balances via RPC)
  writes: ctx.exploits

ValidationEngine
  reads:  ctx.exploits (via archive node fork)
  writes: ctx.validated_exploits

ReportingEngine
  reads:  entire ctx
  writes: report files (JSON + Markdown)
```

---

## Konfigurasi

```yaml
# configs/settings.yaml

analysis:
  timeout_per_contract: 600        # seconds
  max_symbolic_paths: 10000
  max_path_depth: 500
  branch_table_max_visits: 2       # pruning rule
  fallback_to_symbolic: true

rpc:
  url: "${EVM_RPC_URL}"
  timeout: 30
  max_retries: 3

deobfuscation:
  branch_table_offset: 0xe000      # sesuai paper
  intermediate_offset: 0xf000

vulnerability:
  erc20_selectors:
    transfer: "0xa9059cbb"
    transferFrom: "0x23b872dd"
    approve: "0x095ea7b3"
  risky_tokens:
    WETH: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
    WBTC: "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599"
    USDC: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
    USDT: "0xdAC17F958D2ee523a2206206994597C13D831ec7"
    DAI: "0x6B175474E89094C44Da98b954EedeAC495271d0F"
    UNI: "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984"
    LINK: "0x514910771AF9Ca656af840dff83E8264EcF986CA"

exploit_generation:
  adversary_address: "0xDeadDeAddeAddEAddeadDEaDDEAdDeaDDeAD0000"
  max_tokens_per_contract: 7

validation:
  require_transfer_event: true
  simulate_only: true              # NEVER broadcast
```

---

## Dependency Graph (Simplified)

```
z3-solver ──────────────────────┐
                                 ▼
pyevmasm → BytecodeAnalysis → Deobfuscation → CFG
                                                │
py-evm → ConcolicExecution ←───────────────────┘
           │
           ▼
       VulnerabilityEngine
           │
           ▼
       ExploitGeneration (z3-solver + web3.py)
           │
           ▼
       ValidationEngine (py-evm + web3.py)
           │
           ▼
       ReportingEngine (rich + pydantic)
```
