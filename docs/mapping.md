# Threat mapping

Every case carries a `mapping` block with identifiers from two public catalogues.
The harness does not interpret them; they are there so a finding can be filed
against a control framework without re-deriving the classification.

## Category → OWASP Top 10 for LLM Applications (2025)

| Harness category | What the attack tries | OWASP LLM |
| --- | --- | --- |
| `injection.direct` | Instructions placed in the submitted content override the agent's task | LLM01 Prompt Injection |
| `injection.indirect` | Content impersonates a trusted source such as a tool result or runbook | LLM01 Prompt Injection, LLM08 Vector and Embedding Weaknesses (poisoned retrieval) |
| `exfiltration.prompt` | The agent reveals its system prompt or instructions | LLM07 System Prompt Leakage |
| `exfiltration.knowledge` | The agent dumps internal knowledge (runbooks, documents) instead of using it | LLM02 Sensitive Information Disclosure |
| `output.unsafe` | The agent relays attacker-supplied commands or links to a human or downstream system | LLM05 Improper Output Handling |
| `output.fabrication` | The agent claims actions or results it cannot have produced | LLM09 Misinformation |
| `agency.schema` | The agent extends its response contract on request from content | LLM06 Excessive Agency |
| `dos.input` | Inputs outside the documented bounds reach the model | LLM10 Unbounded Consumption |
| `format.robustness` | Malformed requests crash or leak implementation details | LLM10 Unbounded Consumption (resource exhaustion through error paths) |

## MITRE ATLAS techniques used in the cases

| ATLAS ID | Technique | Used by |
| --- | --- | --- |
| AML.T0051 | LLM Prompt Injection | `inj-*`, `output-*`, `agency-*` |
| AML.T0054 | LLM Jailbreak | `inj-003-fake-tool-result` |
| AML.T0056 | LLM Meta Prompt Extraction | `exfil-001-system-prompt` |
| AML.T0057 | LLM Data Leakage | `exfil-002-runbook-text` |
| AML.T0029 | Denial of ML Service | `dos-*` |

## Adding a category

1. Pick a `family.kind` name. The family groups the goal (`injection`, `exfiltration`,
   `output`, `agency`, `dos`, `format`); the kind names the technique.
2. Add a row above with the OWASP and ATLAS identifiers.
3. If the category tolerates a non-zero attack success rate, say so in
   `policy/thresholds.json` with a glob for that category and write down why in
   the policy file's neighbour, not in the case.
