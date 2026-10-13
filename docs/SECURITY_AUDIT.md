# Hostile security audit

## Scope

This review covers policy immutability, authority boundaries, packet
validation, semantic consensus, deterministic charging, cumulative accounting,
replay, closure, storage bounds, and prompt injection.

## Findings and controls

| Threat | Control | Result |
| --- | --- | --- |
| Caller chooses the owner | Owner is derived only from `gl.message.sender_address` | Mitigated |
| Owner authorizes as agent | Owner and agent are distinct; write checks the registered agent | Mitigated |
| Random wallet burns agent budget | Authorization requires the stored agent address | Mitigated |
| Owner refills or raises capacity | No refill, reset, update, override, or capacity mutation entry point exists | Mitigated |
| Closed policy accepts new actions | `ACTIVE` is checked before authorization; close has no reverse transition | Mitigated |
| Caller supplies a low-risk score or charge | Exact seven-key semantic projection rejects numeric and decision fields | Mitigated |
| Prompt injection changes classification | Packet is delimited as untrusted data; leader and validator independently normalize exact enums | Mitigated subject to consensus quality |
| Validator disagreement authorizes | `run_nondet` requires exact normalized equality; failure becomes `UNRESOLVED` | Mitigated |
| Model arithmetic bypasses budget | All charges and total are contract-owned constants and integer addition | Mitigated |
| Rewording resets risk | Semantic class is independent of action ID and every fresh ID consumes again | Mitigated and regression-tested |
| Same action replays without charge | `(policy_id, action_id)` is unique and immutable | Mitigated |
| Denial mutates one dimension | Every remaining check runs before any persistent accounting write | Mitigated and regression-tested |
| Global budget is bypassed through dimensions | Both per-dimension and global remaining checks are mandatory | Mitigated |
| Quantified mismatch bypasses exposure | Exact unit match is deterministic and positive amounts use integer accounting | Mitigated |
| Underflow or overflow breaks counters | Capacities, amounts, and stored counters are bounded; remaining checks reject corrupt state | Mitigated |
| Action-record spam is unbounded | 256-policy and 256-action-per-policy caps plus bounded packet/text sizes | Mitigated within declared limits |
| Malformed semantic output authorizes | JSON shape, exact keys, enum sets, status, and unresolved handling fail closed | Mitigated |
| Inconsistent packet is authorized | `packet_consistency` must be `CONSISTENT`; contradictory is stored as `DENIED` | Mitigated subject to evaluator quality |

## Residual risks

The packet is an input commitment, not an omniscient view of the world. A
caller can omit a dependency or intentionally describe a coordinated strategy
in fragments. RiskBudget cannot observe unreported off-chain activity and does
not aggregate actions submitted through other systems. Semantic consensus can
also be unresolved or incorrect; integrations should require an authorized
record before acting and add domain-specific controls for high-impact actions.

There is no fake time window or automatic refill. A new risk period requires a
new policy, which preserves the historical policy fingerprint and accounting.
