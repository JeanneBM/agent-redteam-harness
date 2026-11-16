"""Agent Red-Team Harness: adversarial regression tests for LLM agents.

The harness sends attack payloads to a running agent, evaluates the responses
with deterministic checks (and an optional LLM judge), and reports the attack
success rate per category against policy thresholds.
"""

__version__ = "0.1.0"
