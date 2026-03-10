# RESEARCH_MODEL.md — AI Reasoning Model for Little Bodi

## Analysis Philosophy

Little Bodi adopts a layered reasoning approach: from the most concrete (bytecode) to the most abstract (vulnerability semantics), and back to the concrete (exploit transaction). This reflects the SKANF paper methodology, which combines static analysis, symbolic reasoning, and concrete validation.

---

## Mental Model: "Attacker Perspective, Defender Purpose"

When analyzing a contract, the reasoning engine must always ask:

> "If I were an attacker who could see all this bytecode, what could I do to transfer tokens from this contract to my account?"

This is not for attacking, but to **identify whether such an attack is possible** before someone else does it.

---

## Reasoning Layers

### Layer 1: Structural Reasoning (CFG Level)
- Question: "Which parts of this code are accessible to anyone?"
- Model: CFG reachability from public entry points
- Output: Set of reachable basic blocks

### Layer 2: Semantic Reasoning (Data Flow Level)
- Question: "Can attacker-controlled data (calldata) influence the output of a CALL instruction?"
- Model: Taint propagation from calldata to CALL parameters
- Output: Tainted CALL parameters

### Layer 3: Constraint Reasoning (Path Level)
- Question: "Under what conditions can this tainted CALL be executed?"
- Model: Path constraints from symbolic execution
- Output: Z3 formula describing the calldata that triggers the vulnerability

### Layer 4: Exploit Reasoning (Concrete Level)
- Question: "Can I construct concrete calldata to steal assets?"
- Model: Z3 constraint solving with asset-theft constraints
- Output: Byte calldata

### Layer 5: Validation Reasoning (Ground Truth Level)
- Question: "Does this exploit actually work in a real environment?"
- Model: Deterministic EVM execution on fork state
- Output: Boolean + event logs

---

## Threat Model Reasoning

According to the paper, the modeled adversary has:

```
Adversary CAPABILITIES:
✓ Create and send transactions
✓ Deploy smart contracts
✓ Read all on-chain data (bytecode, state, transactions)
✓ Control tx.origin via phishing (lure victim into a malicious contract)
✓ Freely choose calldata parameters

Adversary LIMITATIONS:
✗ No private keys of other accounts
✗ Cannot manipulate block ordering (not a validator)
✗ No access to off-chain secrets
```

**Implications for reasoning**:
- When evaluating access control, assume `tx.origin` can be set by the attacker (phishing attacks were proven successful in 104 real cases).
- When evaluating `msg.sender`, assume it is the differentiator — except for callback patterns (uniswapV3SwapCallback, etc.).

---

## Vulnerability Taxonomy

### Type 1: Fully Controllable CALL
```
CALL(
  target = tainted,     ← attacker chooses ERC-20 token
  selector = tainted,   ← attacker sets to transfer
  recipient = tainted,  ← attacker sets to self
  amount = tainted      ← attacker sets to max balance
)
```
**Severity**: Critical. No prior knowledge of the contract required.

### Type 2: Fixed Target, Controllable Recipient
```
CALL(
  target = WETH_ADDRESS,   ← hardcoded
  selector = 0xa9059cbb,   ← hardcoded transfer
  recipient = tainted,     ← attacker controlled
  amount = fixed/tainted
)
```
**Severity**: Critical. Common pattern in MEV bots using WETH.

### Type 3: tx.origin Gated (Requires Phishing)
```
if tx.origin != OWNER_ADDRESS: revert()
CALL(target = tainted, ...)
```
**Severity**: High. Requires a phishing step, but proven easy in practice.

### Type 4: Callback Manipulation
```
// uniswapV3SwapCallback is called by "pool"
// But anyone can create a contract that sends this callback
function uniswapV3SwapCallback(...) {
  CALL(target = tainted, ...)
}
```
**Severity**: High. This is the pattern of 104 real attacks in the paper.

---

## Heuristic Rules for False Positive Reduction

### H1 — Zero Balance Skip
If the contract holds no tokens (zero balance in all tracked tokens), skip exploit generation. The vulnerability might still exist but is not actionable at the moment.

### H2 — CALL Depth Filter
CALLs that are only reachable from internal functions (not public/external) with strong caller checks → downgrade from Critical to Medium.

### H3 — Deterministic Amount Requirement
Vulnerabilities that require the attacker to know the exact balance (and amount is not controllable) → harder to exploit, flag as "partial vulnerability".

### H4 — Revert-on-Zero Filter
If a check `require(amount > 0)` exists before the CALL and the amount is not tainted → cannot transfer zero (but still stealable if there is a balance).

---

## Confidence Scoring

Each vulnerability is assigned a confidence score:

| Condition | Score |
|---|---|
| Exploit validated successfully on local fork | 1.0 (Confirmed) |
| Preliminary validation success, exploit synthesis failed | 0.7 (Likely) |
| Symbolic path feasible, not yet validated | 0.4 (Possible) |
| Only CFG reachability with no concrete evidence | 0.2 (Speculative) |

---

## Reasoning for Obfuscation Detection

A contract is considered obfuscated if:
1. There is an indirect jump (`J` is not empty), OR
2. Code coverage from Gigahorse/CFG analysis < 50%

Deobfuscation is considered successful if:
- Coverage increases to > 90%, OR
- At least one previously undetected vulnerability is found

---

## Reasoning for Prioritization

If multiple vulnerabilities exist, the order for exploit generation is:

1. Highest estimated value (largest token balance)
2. Lowest path constraint complexity (easier to exploit = more urgent)
3. No tx.origin requirement (more direct)
4. Current balance > 0 (actionable right now)
