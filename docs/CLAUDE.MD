# CLAUDE.md — Instruksi untuk Claude Code Agent

## Identitas Proyek

Kamu sedang bekerja pada **Little Bodi**, sebuah EVM bytecode vulnerability analysis engine berbasis Python. Proyek ini mengimplementasikan konsep dari paper "Insecurity Through Obscurity: Veiled Vulnerabilities in Closed-Source Contracts" (Yang et al., 2025).

---

## Prinsip Utama

1. **Modularitas dulu** — setiap engine berdiri sendiri dengan interface yang terdefinisi jelas. Jangan coupling antar engine secara langsung, gunakan abstraksi.
2. **Python 3.12+** — gunakan type hints di seluruh codebase, tidak ada pengecualian.
3. **Tidak ada magic number** — semua konstanta EVM (opcode values, JUMPDEST marker, dll) harus ada di `core/constants.py`.
4. **Test sebelum integrasi** — setiap engine harus punya unit test minimal sebelum diintegrasikan ke pipeline.
5. **Fail loudly** — gunakan custom exceptions bukan generic `Exception`. Semua error harus informatif dan traceable.

---

## Konvensi Kode

### Struktur File
```python
# Setiap file engine harus mengikuti pola ini:
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, List
import logging

logger = logging.getLogger(__name__)

@dataclass
class EngineInput:
    ...

@dataclass  
class EngineOutput:
    ...

class SomeEngine:
    def __init__(self, config: dict) -> None:
        ...
    
    def run(self, input: EngineInput) -> EngineOutput:
        ...
```

### Naming Conventions
- Classes: `PascalCase`
- Functions/methods: `snake_case`
- Constants: `UPPER_SNAKE_CASE`
- Private methods: `_prefixed_with_underscore`
- File names: `snake_case.py`

### EVM-Specific Naming
- Gunakan nama opcode persis seperti di EVM spec: `JUMP`, `JUMPI`, `JUMPDEST`, `CALL`, `CALLDATALOAD`
- Alamat Ethereum selalu dalam format checksum: `Web3.to_checksum_address()`
- Bytecode selalu sebagai `bytes` bukan `str` kecuali untuk display
- PC (Program Counter) selalu `int`

---

## Arsitektur Engine

Setiap engine mengikuti interface ini:

```python
class BaseEngine(ABC):
    @abstractmethod
    def run(self, context: AnalysisContext) -> EngineResult:
        pass
    
    @abstractmethod
    def validate_input(self, context: AnalysisContext) -> bool:
        pass
```

Pipeline memanggil engine secara berurutan:
```
BytecodeAnalysisEngine
    → DeobfuscationEngine
        → SymbolicExecutionEngine / ConcolicEngine
            → VulnerabilityEngine
                → ExploitGenerationEngine
                    → ValidationEngine
                        → ReportingEngine
```

---

## Hal yang TIDAK Boleh Dilakukan

- Jangan hardcode RPC URL — gunakan environment variable `EVM_RPC_URL`
- Jangan simpan private key di kode — hanya alamat publik untuk simulasi
- Jangan gunakan `eval()` atau `exec()` untuk proses bytecode
- Jangan skip validasi input di awal setiap engine
- Jangan catch semua exception dengan `except Exception` tanpa log yang jelas
- Jangan buat dependency circular antar engine

---

## Cara Kerja Analisis EVM yang Perlu Kamu Pahami

### Indirect Jump
```
PUSH value_from_calldata
JUMP  ← ini indirect, tujuan tidak diketahui statically
```
SKANF/Little Bodi mengatasinya dengan membangun branch table:
```
PUSH 0xe000  ← redirect ke branch table
JUMP
; di 0xe000:
DUP1
PUSH2 0x0a00  ← destination 1
EQ
PUSH2 0xf000
JUMPI
; ... dst
```

### Vulnerability Oracle
CALL instruction dianggap vulnerable jika:
1. Reachable dari public entry point
2. Target address: adversary-controllable ATAU adalah ERC-20 token contract
3. Function selector: adversary-controllable ATAU `transfer`/`approve`
4. Argument pertama (recipient): adversary-controllable

### Taint Analysis
- Source: `CALLDATALOAD`, `CALLDATACOPY`
- Propagation: semua arithmetic/logical/copy ops (conservative)
- Sink: parameter CALL instruction (target, selector, args)

---

## Dependencies Utama

```
py-evm>=0.9.0
pyevmasm>=0.2.3
z3-solver>=4.13.0
web3>=7.0.0
networkx>=3.3
click>=8.1.0
pydantic>=2.7.0
pytest>=8.2.0
aiohttp>=3.9.0
rich>=13.7.0       # untuk CLI output
```

---

## Cara Menjalankan

```bash
# Single contract analysis
python scripts/analyze.py --bytecode 0x... --rpc $EVM_RPC_URL

# Dari file bytecode
python scripts/analyze.py --bytecode-file contract.bin --address 0x...

# Dengan historical transactions
python scripts/analyze.py --address 0x... --rpc $EVM_RPC_URL --use-history

# Batch mode
python scripts/batch_analyze.py --addresses addresses.txt --output results/
```

---

## Output yang Diharapkan

```json
{
  "contract_address": "0x...",
  "analysis_timestamp": "2025-...",
  "obfuscated": true,
  "coverage_before": 12.3,
  "coverage_after": 98.7,
  "vulnerabilities": [
    {
      "call_pc": "0xac5",
      "type": "asset_management",
      "target_address": "adversary_controllable",
      "function_selector": "0xa9059cbb",
      "recipient": "adversary_controllable",
      "amount": "adversary_controllable",
      "exploit_generated": true,
      "exploit_validated": true
    }
  ],
  "exploits": [...],
  "estimated_loss_usd": 0.0
}
```

---

## Testing Guidelines

```bash
# Unit tests
pytest tests/unit/ -v

# Integration tests (butuh archive node)
pytest tests/integration/ -v --rpc $EVM_RPC_URL

# Specific engine
pytest tests/unit/test_deobfuscation.py -v
```

Gunakan fixture bytecode dari `tests/fixtures/` untuk unit tests — jangan hit RPC di unit tests.