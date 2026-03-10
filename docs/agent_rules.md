# agent_rules.md — AI Coding Agent Rules for Little Bodi

## Work Priorities

1. **Correctness** > Performance > Code Elegance
2. One engine = one responsibility. No scope creep.
3. Every PR/commit must be explainable in a single sentence.

---

## Mandatory Rules

### R01 — Always Verify EVM Spec
Before implementing any opcode behavior, check the EVM Yellow Paper or `pyevmasm` docs. Do not assume opcode semantics.

### R02 — Bytecode is Immutable Input
Bytecode received from the user is never modified in-place. All transformations (deobfuscation, instrumentation) produce a new representation, not an overwrite.

### R03 — Symbolic Variables Must be Typed
Every symbolic variable must have an explicit type (uint256, bytes32, address, etc.). Z3 bitvectors must match the EVM word size (256-bit).

```python
# Correct
from z3 import BitVec
sym_calldata = BitVec('calldata_0', 256)

# Incorrect
sym_calldata = Int('calldata_0')  # Z3 Int is unbounded
```

### R04 — Path Explosion Protection
Symbolic execution MUST have exploration limits:
- Max paths per contract: configurable, default 10,000
- Max depth per path: configurable, default 500
- Timeout per contract: configurable, default 600 seconds

### R05 — Taint Analysis is Conservative
If in doubt whether a value is tainted, assume it is tainted. A false positive vulnerability is more acceptable than a false negative during the detection phase (validation will filter them out).

### R06 — Exploit Generation Must be Idempotent
The same exploit at the same block height must produce the same calldata. Use a deterministic seed for constraint solving.

### R07 — No Live Broadcasts
The exploit generation and validation engines operate **only** on a local fork. No transactions are broadcast to mainnet, testnet, or any other network. This is a defensive tool, not an attack tool.

### R08 — Address Handling
```python
# Always use checksum addresses
from web3 import Web3
addr = Web3.to_checksum_address("0xdead...beef")

# For adversary simulation, use a constant
ADVERSARY_ADDR = "0xDeadDeAddeAddEAddeadDEaDDEAdDeaDDeAD0000"
```

### R09 — Logging Levels
- `DEBUG`: per-opcode details, constraint values
- `INFO`: progress per stage, coverage stats
- `WARNING`: timeout, path pruned, fallback activated
- `ERROR`: engine failure, invalid bytecode
- `CRITICAL`: only for unrecoverable state

### R10 — Do Not Re-implement Existing Tools
- EVM execution: use `py-evm`
- Disassembly: use `pyevmasm`
- Constraint solving: use `z3-solver`
- Unless there is a clear technical reason why the library is insufficient

---

## Rules for EVM Analysis

### R11 — JUMPDEST Enumeration
Scan bytecode from offset 0 to collect all valid JUMPDESTs before building the branch table. JUMPDESTs inside PUSH data (not instructions) must be ignored.

```python
def collect_jumpdests(bytecode: bytes) -> set[int]:
    """
    JUMPDEST is valid only if it is outside of PUSH data.
    """
    jumpdests = set()
    i = 0
    while i < len(bytecode):
        op = bytecode[i]
        if op == 0x5B:  # JUMPDEST
            jumpdests.add(i)
        elif 0x60 <= op <= 0x7F:  # PUSH1-PUSH32
            push_size = op - 0x60 + 1
            i += push_size  # skip push data
        i += 1
    return jumpdests
```

### R12 — ERC-20 Token Detection
A contract is considered an ERC-20 if the bytecode contains the function selector `0xa9059cbb` (transfer) or `0x23b872dd` (transferFrom). Additional verification via on-chain ABI if an archive node is available.

### R13 — tx.origin vs msg.sender
Vulnerabilities that require control of tx.origin are classified as "requires phishing". These are still valid vulnerabilities because the paper shows that 141 out of 394 real exploits required tx.origin control.

### R14 — Block State for Validation
Exploits must be validated at the same block height as when the vulnerability was detected. Use an archive node to load the correct historical state.

---

## Rules for Output

### R15 — JSON Output Must be Schema-Validated
Use Pydantic models for all structured output. Do not return raw dicts from one engine to another.

### R16 — Monetary Loss Estimation is a Lower Bound
Always label loss estimates as a "lower bound" because they only account for 7 major tokens (WETH, WBTC, USDC, USDT, DAI, UNI, LINK).

### R17 — Reports Must be Actionable
Every vulnerability in a report must include:
- PC of the vulnerable CALL
- Which parameters are controllable
- Whether the exploit was successfully validated
- Mitigation recommendation (at least one)

---

## Anti-Patterns to Avoid

| Anti-Pattern | Reason |
|---|---|
| `except Exception: pass` | Hides critical bugs |
| Modifying bytecode bytes directly | Breaks offset analysis |
| Z3 Int for EVM values | Integers are unbounded; EVM is 256-bit |
| Hardcoding block numbers | Makes tests non-reproducible |
| Skipping preliminary validation | Many false positives from symbolic execution |
| Infinite symbolic loops | Requires visited-state deduplication |
| Taint only for explicit flow | Too many false negatives |
