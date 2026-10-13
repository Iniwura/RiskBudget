# RiskBudget architecture

RiskBudget is a standalone GenLayer Intelligent Contract for semantic rate
limiting of autonomous agents. It creates a finite policy for one registered
agent, classifies each submitted action into bounded semantic facts, maps those
facts to protocol-owned integer charges, and consumes budget only when every
check passes.

## State model

`PolicyRecord` freezes the owner, agent, quantified unit, every capacity, and a
SHA-256 policy fingerprint at creation. Only `ACTIVE` and `CLOSED` exist. The
owner can close a policy once; there is no reopen, refill, reset, capacity
increase, admin override, or clock-based epoch.

`ActionRecord` is keyed by `(policy_id, action_id)`. It stores the exact
canonical packet, the normalized semantic projection, both fingerprints, the
decision, reason, and deterministic attempted charges. Each action ID is
recorded once, including denied and unresolved attempts. The bounded action
capacity prevents storage spam.

## Consensus boundary

`authorize_action` has exactly one `gl.vm.run_nondet` boundary. The leader and
validator each call `gl.nondet.exec_prompt` independently. Normalization
requires exactly seven keys and only bounded enum values. Extra keys such as
`risk_score`, `allow`, or `charge`, missing keys, malformed JSON, invalid enums,
and validator disagreement fail closed as `UNRESOLVED`.

The model returns facts only:

```json
{
  "data_exposure": "SENSITIVE",
  "external_reach": "PUBLIC",
  "privilege_effect": "NONE",
  "irreversibility": "REVERSIBLE",
  "blast_radius": "LOCAL",
  "packet_consistency": "CONSISTENT",
  "semantic_status": "COMPLETE"
}
```

The model never returns a numeric score or authorization decision. The packet
is surrounded by untrusted-data delimiters and all its fields are treated as
data, including prompt-injection text.

## Deterministic accounting

The fixed charge table is:

| Dimension | Values |
| --- | --- |
| data | `NONE=0`, `INTERNAL=1`, `SENSITIVE=3`, `RESTRICTED=5` |
| external reach | `NONE=0`, `PRIVATE=1`, `LIMITED=2`, `PUBLIC=4` |
| privilege | `NONE=0`, `USE_EXISTING=1`, `MODIFY_ACCESS=4`, `ADMINISTRATIVE=6` |
| irreversibility | `REVERSIBLE=0`, `COSTLY_REVERSAL=2`, `IRREVERSIBLE=5` |
| blast radius | `LOCAL=0`, `SERVICE=2`, `CROSS_SYSTEM=4` |

`total_charge` is the sum of the five dimension charges. An authorization
requires `COMPLETE`, `CONSISTENT`, no unresolved dimension, a matching
quantified unit, enough quantified exposure, enough remaining capacity in
every dimension, and enough global total capacity. Only then are all consumed
counters incremented in the same write. Denied and unresolved actions never
change consumed counters.

Quantified exposure is an integer amount. A positive amount must use the
policy's exact normalized unit and must fit the remaining exposure. No model
comparison or floating-point arithmetic is involved.

## Public surface

Writes: `create_policy`, `authorize_action`, `close_policy`.

Views: `get_policy`, `get_action`, `get_policy_fingerprint`,
`get_action_fingerprint`, `get_remaining_budget`, and
`get_policy_action_ids`.

The extracted ABI is checked in at
`schema/risk_budget.schema.json`.
