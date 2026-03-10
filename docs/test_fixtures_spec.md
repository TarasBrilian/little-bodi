# test_fixtures_spec.md — Fixture Specifications for Unit Tests

## Principles

Unit tests MUST NOT hit the RPC or archive node. All bytecode fixtures are static bytes committed to the repo. Integration tests may hit the RPC but must use an explicit `--rpc` flag when run.

---

## Fixtures Directory Structure

```
tests/
├── fixtures/
│   ├── bytecode/
│   │   ├── simple_jump.hex         # Direct JUMP (non-obfuscated)
│   │   ├── indirect_jump.hex       # One indirect JUMP from calldata
│   │   ├── indirect_jumpi.hex      # One indirect JUMPI from calldata
│   │   ├── multi_indirect.hex      # Multiple indirect jumps
│   │   ├── vulnerable_transfer.hex # Contract with open ERC-20 transfer
│   │   ├── phishing_origin.hex     # Contract with tx.origin check + open transfer
│   │   ├── safe_contract.hex       # Valid contract, no vulnerability
│   │   └── push_disguised.hex      # 0x5B inside PUSH data (not a JUMPDEST)
│   ├── transactions/
│   │   ├── seed_valid.json         # Valid historical tx as seed
│   │   └── seed_no_erc20.json      # Historical tx without ERC-20 transfer
│   └── reports/
│       └── expected_output.json    # Expected JSON output for vulnerable_transfer.hex
```

---

## Bytecode Fixtures — Detail

### simple_jump.hex
Contract with one JUMP to a hardcoded PUSH constant.
```
PUSH2 0x0008   ; 61 0008
JUMP           ; 56
INVALID        ; FE  (dead code, not a target)
JUMPDEST       ; 5B  (PC=8, valid target)
STOP           ; 00
```
Hex: `610008 56 FE 5B 00`  
Expected: `indirect_jumps = []`, `jumpdests = {8}`, coverage = 100%

---

### indirect_jump.hex
Contract with one indirect JUMP from calldata (pattern from paper).
```
PUSH1 0x00     ; 6000
CALLDATALOAD   ; 35    ← load calldata[0:32]
PUSH1 0xF0     ; 60F0
SHR            ; 1C    ← v = calldata >> 0xF0 (top 2 bytes as selector/dest)
JUMP           ; 56    ← INDIRECT: destination from calldata
JUMPDEST       ; 5B    (PC=7)
STOP           ; 00
JUMPDEST       ; 5B    (PC=9)
RETURN         ; F3
```
Hex: `6000 35 60F0 1C 56 5B 00 5B F3`  
Expected:
- `indirect_jumps = [{pc: 5, depends_on: ["calldata"]}]`
- `jumpdests = {7, 9}`
- `coverage_before < 50%` (only entry block reachable)
- `coverage_after = 100%` after deobfuscation

---

### indirect_jumpi.hex
Like indirect_jump.hex but using JUMPI.
```
PUSH1 0x00     ; 6000
CALLDATALOAD   ; 35
PUSH1 0xF0     ; 60F0
SHR            ; 1C    ← destination
PUSH1 0x01     ; 6001  ← condition (always true)
JUMPI          ; 57    ← INDIRECT JUMPI
JUMPDEST       ; 5B    (PC=8, fall-through)
STOP           ; 00
JUMPDEST       ; 5B    (PC=10)
RETURN         ; F3
```
Expected:
- `indirect_jumps = [{pc: 7, opcode: JUMPI, depends_on: ["calldata"]}]`
- SWAP1 + PUSH 0xe000 handling must be verified

---

### push_disguised.hex
0x5B inside PUSH data — NOT a valid JUMPDEST.
```
PUSH2 0x5B5B   ; 61 5B 5B  ← both 0x5B are PUSH operands, not JUMPDESTs
PUSH1 0x08     ; 6008
JUMP           ; 56
INVALID        ; FE
JUMPDEST       ; 5B  (PC=8 — valid one)
STOP           ; 00
```
Hex: `61 5B5B 6008 56 FE 5B 00`  
Expected: `jumpdests = {8}` — PC=1 and PC=2 are NOT jumpdests even though the byte is 0x5B

---

### vulnerable_transfer.hex
Simple contract that directly exposes ERC-20 transfer without access control.
```
; Entry: load calldata and directly call transfer
PUSH1 0x24     ; arg2 (amount) offset
CALLDATALOAD   ; load amount from calldata
PUSH1 0x04     ; arg1 (recipient) offset
CALLDATALOAD   ; load recipient from calldata
PUSH4 0xa9059cbb ; transfer function selector
... (construct calldata for call)
PUSH20 <WETH>  ; hardcoded target = WETH
CALL           ; ← VULNERABLE: all parameters from calldata
STOP
```
Expected:
- `potential_vulnerabilities` has 1 entry
- `call_pc` = offset of CALL instruction
- `target_address.is_risky_fixed = True` (WETH hardcoded)
- `function_selector.is_risky_fixed = True` (transfer selector)
- `recipient_arg.is_adversary_controllable = True`

---

### phishing_origin.hex
Contract with tx.origin check followed by vulnerable transfer (Destroyer Inu pattern).
```
; Check tx.origin
ORIGIN         ; 32
PUSH20 0xdead...beef  ; hardcoded owner
EQ             ; compare
PUSH1 0x2A     ; destination if match
JUMPI          ; conditional jump
REVERT         ; reject if not owner
JUMPDEST       ; 0x2A — enter here if tx.origin == owner
; Transfer logic with calldata-controlled parameters
...
CALL           ; ← VULNERABLE but requires phishing
STOP
```
Expected:
- `potential_vulnerabilities[0].requires_tx_origin_control = True`

---

### safe_contract.hex
Contract with proper access control — no vulnerability.
```
; Strict msg.sender check
CALLER         ; 33
PUSH20 0xdead...beef
EQ
ISZERO
PUSH1 END
JUMPI
; Only transfer to hardcoded address with hardcoded amount
PUSH32 <fixed_amount>
PUSH20 <fixed_recipient>
PUSH4 0xa9059cbb
... fixed call ...
CALL
STOP
```
Expected: `potential_vulnerabilities = []`

---

## Transaction Fixtures

### seed_valid.json
```json
{
  "tx_hash": "0xabcd...",
  "from": "0x1234...",
  "to": "0xCONTRACT...",
  "calldata": "0x...",
  "value": "0",
  "block_number": 20000000,
  "status": 1,
  "erc20_transfers": [
    {
      "token": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
      "from": "0xCONTRACT...",
      "to": "0xDEX...",
      "amount": "1000000000000000000"
    }
  ]
}
```

### seed_no_erc20.json
```json
{
  "tx_hash": "0xef01...",
  "from": "0x5678...",
  "to": "0xCONTRACT...",
  "calldata": "0x",
  "value": "0",
  "block_number": 20000001,
  "status": 1,
  "erc20_transfers": []
}
```
Expected: this seed must be filtered out by SeedExtractor.

---

## How to Create New Fixtures

```bash
# From Solidity source (if available)
solc --bin-runtime --optimize MyContract.sol | tail -1 > tests/fixtures/bytecode/my_contract.hex

# From manual hex string
echo "6000355B00" > tests/fixtures/bytecode/minimal.hex

# Verify valid hex
python -c "bytes.fromhex(open('tests/fixtures/bytecode/minimal.hex').read().strip())"
```

---

## Confirming Fixture Format

- `.hex` files: plain hex string, no `0x` prefix, no newline at end
- `.json` files: valid JSON, UTF-8

```python
# Helper in conftest.py
import pytest
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures"

@pytest.fixture
def bytecode_indirect_jump() -> bytes:
    hex_str = (FIXTURES_DIR / "bytecode" / "indirect_jump.hex").read_text().strip()
    return bytes.fromhex(hex_str)

@pytest.fixture
def bytecode_vulnerable_transfer() -> bytes:
    hex_str = (FIXTURES_DIR / "bytecode" / "vulnerable_transfer.hex").read_text().strip()
    return bytes.fromhex(hex_str)

@pytest.fixture
def bytecode_safe() -> bytes:
    hex_str = (FIXTURES_DIR / "bytecode" / "safe_contract.hex").read_text().strip()
    return bytes.fromhex(hex_str)
```
