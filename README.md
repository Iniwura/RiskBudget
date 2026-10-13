# RiskBudget

RiskBudget is a standalone GenLayer Intelligent Contract for semantic rate
limiting of autonomous agents. Traditional rate limits count exact requests or
method names. RiskBudget projects differently worded actions onto bounded risk
dimensions, derives fixed protocol charges, and consumes an immutable finite
budget cumulatively.

For example, two differently worded public announcements both project to
`external_reach=PUBLIC` and each consume the fixed `PUBLIC=4` charge. With an
external budget of 8, the third equivalent action is denied. Rewording cannot
reset the counter because action identity is separate from semantic class and
fresh action IDs intentionally represent fresh attempted actions.

## Contract rules

- The owner is always taken from `gl.message.sender_address`.
- Each policy registers exactly one agent and freezes all capacities forever.
- The model returns only bounded semantic facts; it cannot choose scores,
  weights, charges, or authorization.
- The contract maps facts to a fixed deterministic charge table.
- Quantified amounts are integer-accounted and require the policy's exact unit.
- Authorization and all budget consumption happen atomically in one write.
- `DENIED` and `UNRESOLVED` actions do not consume budget; their records remain
  readable for audit.
- Only `ACTIVE` and `CLOSED` states exist. Closing is owner-only and irreversible.
- There is no daily, hourly, weekly, or automatic reset because GenVM does not
  expose a reliable enforceable on-chain clock for this policy.
- Storage is bounded by 256 policies, 256 actions per policy, bounded text,
  bounded packet size, and bounded integer capacities.

## Action packet

`authorize_action(policy_id, action_id, action_packet)` accepts exactly:

```json
{
  "action": "Publish the quarterly release announcement",
  "target": "company public social account",
  "resource": "communications account",
  "purpose": "announce the product release",
  "amount": 0,
  "amount_unit": "USD",
  "data_handled": "public release information",
  "audience": "general public",
  "side_effects": "creates a permanent public post",
  "constraints": "single post"
}
```

All text is untrusted data. The contract validates exact keys, non-empty bounded
fields, integer amount semantics, and canonical JSON before consensus.

## Fixed charge table

| Dimension | Fixed mapping |
| --- | --- |
| data exposure | `NONE=0`, `INTERNAL=1`, `SENSITIVE=3`, `RESTRICTED=5` |
| external reach | `NONE=0`, `PRIVATE=1`, `LIMITED=2`, `PUBLIC=4` |
| privilege effect | `NONE=0`, `USE_EXISTING=1`, `MODIFY_ACCESS=4`, `ADMINISTRATIVE=6` |
| irreversibility | `REVERSIBLE=0`, `COSTLY_REVERSAL=2`, `IRREVERSIBLE=5` |
| blast radius | `LOCAL=0`, `SERVICE=2`, `CROSS_SYSTEM=4` |

`total_charge` is deterministic addition of the five dimension charges. An
action must fit every applicable dimension and the global total before any
counter changes.

## Local verification

The project targets Studio Dev (`chainId 61997`) and pins the Studio Dev
runner in `contracts/risk_budget.py`.

```bash
source /home/ini/materialproof/.venv/bin/activate
export GENVM_VERSION=vstudio-dev
pytest
genvm-lint check contracts/risk_budget.py
genvm-lint schema contracts/risk_budget.py -o schema/risk_budget.schema.json
genvm-lint typecheck contracts/risk_budget.py
pyright
git diff --check
```

The suite includes policy and packet bounds, owner/agent access, closure,
fingerprints, quantified exposure, all charge dimensions, rewording,
exhaustion boundaries, atomicity, replay, prompt injection, malformed and
extra-key responses, validator disagreement, unresolved handling, and
historical denied records.

## Limitations

RiskBudget only governs actions submitted through this contract. It cannot
detect unreported off-chain actions or coordinated multi-action strategies that
deliberately hide their combined real-world effect. Semantic projection can be
unresolved or wrong; integrations should require successful authorization
before performing the off-chain action and should add domain-specific controls.

There is no frontend in this repository.

Deployment and live smoke evidence are recorded in [PORTAL.md](PORTAL.md), the
hostile review is in [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md), and the
submission summary is in [SUBMISSION.md](SUBMISSION.md).
