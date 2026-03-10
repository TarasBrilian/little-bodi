# setup.md — Scaffold & Getting Started

## Prerequisites

- Python 3.12+
- pip or uv (uv recommended for speed)
- Git
- Archive node RPC (optional, for full concolic mode)
  - Free: Alchemy, Infura, or QuickNode free tier
  - Self-hosted: Reth (`reth node --full`) — recommended for production

---

## Project Scaffold (Run once)

```bash
# 1. Create project directory
mkdir little_bodi && cd little_bodi

# 2. Init git
git init

# 3. Setup Python environment
python3.12 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Create directory structure
mkdir -p \
  core/bytecode_analysis \
  core/deobfuscation \
  core/symbolic_execution \
  core/concolic_execution \
  core/vulnerability \
  core/exploit_generation \
  core/validation \
  core/reporting \
  engines \
  data/seeds \
  data/results \
  tests/unit \
  tests/integration \
  tests/fixtures/bytecode \
  tests/fixtures/transactions \
  tests/fixtures/reports \
  scripts \
  configs

# 6. Create __init__.py in all packages
find core tests engines -type d -exec touch {}/__init__.py \;
touch little_bodi/__init__.py

# 7. Copy files from documentation to the correct locations
cp core_constants.py core/constants.py
cp pipeline_orchestrator.py core/pipeline.py

# 8. Create .env from template
cp .env.example .env
# Edit .env and fill in EVM_RPC_URL

# 9. Verify setup
python -c "from core.constants import OPCODE_TABLE; print('OK:', len(OPCODE_TABLE), 'opcodes')"
python -c "from core.pipeline import AnalysisPipeline; print('OK: Pipeline importable')"
```

---

## .env.example

```bash
# Copy this to .env and fill in appropriate values
EVM_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY_HERE
ETHERSCAN_API_KEY=YOUR_ETHERSCAN_KEY_HERE

# Optional: override defaults
LITTLE_BODI_TIMEOUT=600
LITTLE_BODI_MAX_PATHS=10000
LITTLE_BODI_OUTPUT_DIR=data/results
```

---

## Final File Structure

After scaffolding, the project structure should look like this:

```
little_bodi/
│
├── core/
│   ├── __init__.py
│   ├── constants.py              ← FROM: core_constants.py
│   ├── pipeline.py               ← FROM: pipeline_orchestrator.py
│   ├── bytecode_analysis/
│   │   ├── __init__.py
│   │   └── engine.py             ← IMPLEMENT: BytecodeAnalysisEngine
│   ├── deobfuscation/
│   │   ├── __init__.py
│   │   └── engine.py             ← IMPLEMENT: DeobfuscationEngine
│   ├── symbolic_execution/
│   │   ├── __init__.py
│   │   ├── engine.py             ← IMPLEMENT: SymbolicExecutionEngine
│   │   ├── state.py              ← SymbolicState, TaintMap
│   │   └── interpreter.py        ← SymbolicEVMInterpreter
│   ├── concolic_execution/
│   │   ├── __init__.py
│   │   ├── engine.py             ← IMPLEMENT: ConcolicEngine
│   │   └── seed_extractor.py     ← SeedExtractor
│   ├── vulnerability/
│   │   ├── __init__.py
│   │   └── engine.py             ← IMPLEMENT: VulnerabilityEngine + Oracle
│   ├── exploit_generation/
│   │   ├── __init__.py
│   │   ├── engine.py             ← IMPLEMENT: ExploitGenerationEngine
│   │   └── synthesizer.py        ← CalldataSynthesizer
│   ├── validation/
│   │   ├── __init__.py
│   │   ├── engine.py             ← IMPLEMENT: ValidationEngine
│   │   └── local_fork.py         ← LocalEVMFork
│   └── reporting/
│       ├── __init__.py
│       └── engine.py             ← IMPLEMENT: ReportingEngine
│
├── data/
│   ├── seeds/                    ← cache seed transactions
│   └── results/                  ← output reports
│
├── tests/
│   ├── conftest.py               ← fixtures definitions
│   ├── unit/
│   │   ├── test_bytecode_analysis.py
│   │   ├── test_deobfuscation.py
│   │   ├── test_symbolic_execution.py
│   │   ├── test_concolic_execution.py
│   │   ├── test_vulnerability.py
│   │   └── test_exploit_generation.py
│   ├── integration/
│   │   └── test_full_pipeline.py
│   └── fixtures/
│       ├── bytecode/             ← .hex files
│       ├── transactions/         ← .json files
│       └── reports/              ← expected output .json
│
├── scripts/
│   ├── analyze.py                ← CLI single contract
│   └── batch_analyze.py          ← CLI batch mode
│
├── configs/
│   └── settings.yaml
│
├── requirements.txt
├── .env.example
├── .env                          ← DO NOT commit this
├── .gitignore
├── pytest.ini
└── README.md
```

---

## configs/settings.yaml

```yaml
analysis:
  timeout_per_contract: 600
  max_symbolic_paths: 10000
  max_path_depth: 500
  branch_table_max_visits: 2
  fallback_to_symbolic: true
  max_seeds: 50

deobfuscation:
  branch_table_offset: 0xe000
  intermediate_offset: 0xf000

vulnerability:
  adversary_address: "0xDeadDeAddeAddEAddeadDEAdDeaDDeAD0000"
  max_tokens_per_contract: 7

exploit_generation:
  gas_limit: 1000000
  gas_price_gwei: 20

validation:
  require_transfer_event: true
  simulate_only: true

output:
  dir: "data/results"
  formats:
    - json
    - markdown
```

---

## pytest.ini

```ini
[pytest]
asyncio_mode = auto
timeout = 120
testpaths = tests
markers =
    unit: Unit tests (no RPC required)
    integration: Integration tests (requires --rpc flag)
    slow: Slow tests (>30s)
```

---

## .gitignore

```
.venv/
__pycache__/
*.pyc
.env
data/results/
data/seeds/
*.egg-info/
.pytest_cache/
.mypy_cache/
.ruff_cache/
```

---

## Recommended Implementation Order

Implement engines in this order for incremental testing:

```
1. core/constants.py          ← exists
2. core/pipeline.py           ← exists (stub)
3. core/bytecode_analysis/engine.py
   └─ test: test_bytecode_analysis.py (using indirect_jump.hex fixture)

4. core/deobfuscation/engine.py
   └─ test: test_deobfuscation.py (coverage before/after)

5. core/symbolic_execution/state.py + interpreter.py
6. core/symbolic_execution/engine.py
   └─ test: test_symbolic_execution.py (taint propagation)

7. core/concolic_execution/seed_extractor.py
8. core/concolic_execution/engine.py
   └─ test: test_concolic_execution.py (mock RPC)

9. core/vulnerability/engine.py
   └─ test: test_vulnerability.py (using vulnerable_transfer.hex fixture)

10. core/exploit_generation/synthesizer.py + engine.py
    └─ test: test_exploit_generation.py (Z3 synthesis)

11. core/validation/local_fork.py + engine.py
    └─ test: integration/test_full_pipeline.py

12. core/reporting/engine.py
13. scripts/analyze.py + scripts/batch_analyze.py

14. Wire everything to core/pipeline.py (uncomment imports)
```

---

## How to Run Tests

```bash
# Unit tests only (fast, no RPC needed)
pytest tests/unit/ -v

# With coverage report
pytest tests/unit/ --cov=core --cov-report=term-missing

# One specific engine
pytest tests/unit/test_deobfuscation.py -v

# Integration tests (requires RPC)
pytest tests/integration/ -v --rpc $EVM_RPC_URL

# All tests with timeout
pytest tests/ --timeout=120
```

---

## Quick Smoke Test

Once all engines are implemented, run this to verify:

```python
# smoke_test.py
from core.pipeline import analyze_contract

# Simple bytecode: STOP
result = analyze_contract(
    bytecode_hex="00",
    contract_address=None,
)
print("Errors:", result.errors)
print("Vulnerabilities:", len(result.potential_vulnerabilities))
assert result.errors == [], f"Unexpected errors: {result.errors}"
print("Smoke test passed.")
```

```bash
python smoke_test.py
```

---

## How to Run Analysis

```bash
# Analyze one contract (bytecode from RPC)
python scripts/analyze.py \
  --address 0xYOUR_CONTRACT \
  --rpc $EVM_RPC_URL \
  --output data/results/

# Analyze from local bytecode file
python scripts/analyze.py \
  --bytecode-file contract.bin \
  --output data/results/

# Batch analysis from address list
python scripts/batch_analyze.py \
  --addresses mev_bots.txt \
  --rpc $EVM_RPC_URL \
  --output data/results/ \
  --workers 4
```
