# RiskBudget submission

RiskBudget is a semantic rate limiter for autonomous agents. It freezes a
finite policy for one agent, classifies bounded action packets through strict
GenLayer consensus, derives deterministic charges from fixed protocol tables,
and atomically consumes cumulative risk and quantified-exposure budgets.

It is deliberately distinct from authority containment, concurrency locking,
approval quorum, duplicate detection, and generic model-generated risk scores.

## Release facts

```text
project_path: /home/ini/riskbudget
network: Studio Dev
chain_id: 61997
test_count: 80
test_result: PASS
runner_pin: 5jycge4q8k23462jtb0b9fyey1s9qz928sz2nbrd9mg4sxqg2qng
genlayer_cli_version: 0.40.0-rc.3
genlayer_py_version: 0.16.3
genlayer_test_version: 0.29.2
genvm_version: vstudio-dev
lint_result: PASS
validation_result: PASS
typecheck_result: PASS
schema_result: PASS
source_sha256: 1040fb46fff4beba48c18514888d2aadec46b7d5298ea11091fb007badf41bbc
deployed: FINALIZED / Accepted
deployment_tx: 0xc71419f62cf2a97a13c0bc9aa623db15fca2a2133cf6984d083d97dfb08cc498
contract_address: 0x0492f53482231327366312C9A7C38e058Cc20BBB
fee_value: 100000000000010352 wei
consensus_status: MAJORITY_AGREE
execution_status: FINISHED_WITH_RETURN
source_readback: genlayer code + gen_getContractCode
source_sha_match: TRUE
github: https://github.com/Iniwura/RiskBudget
commit: PENDING
pushed: PENDING
secret_scan: PENDING
live_smoke: PASS
ready_for_submission: PENDING
```

Explorer: https://explorer-studio.genlayer.com/address/0x0492f53482231327366312C9A7C38e058Cc20BBB

The source readback was byte-for-byte identical to the frozen local source.
The live policy `live-risk-20261013` was created by
`0xA35dc047f9937BF668743efBDF8Ea93B31A55888` for agent
`0x30Fd7e8539A8462591e62894739C6864E9B81fa2`, then closed by its owner.
Receipt-backed view calls reported `state=CLOSED`, `action_count=3`,
`consumed_external_units=8`, `consumed_total_risk_units=18`, and
`consumed_quantified_exposure=0`.

Live action evidence:

- A `smoke-a-20261013`: tx
  `0x14a449f5605283c8431d53756279335cecea1917634926b5f3241566d5ba7ff8`,
  `AUTHORIZED`, total charge 9, external charge 4.
- B `smoke-b-retry-20261013`: tx
  `0x975c3b41f612cdb129af0b193fabc99afa9eae68482b25cf17c45198fb76005f`,
  `AUTHORIZED`, total charge 9, external charge 4. The first equivalent
  submission (`0x65409077104a8fac562c3a2975b2dd11fb55968de6f5d345f6817cff92eb93b7`)
  finalized `MAJORITY_DISAGREE / Undetermined` and did not create an action.
- C `smoke-c-20261013`: tx
  `0xad0112e06d84400d6e08d9f3b174109b0e3922e7c5b5edebf8612f643d2b2299`,
  `DENIED`, reason `EXTERNAL_BUDGET_EXCEEDED`, total charge 9, external
  charge 4; the final policy counter remained at 8.
- Close tx:
  `0xf0aba7e2c79a5d4501b9ebb57acff400fb80ecc4f2817a72391d80eea3d19d22`,
  finalized `MAJORITY_AGREE / FINISHED_WITH_RETURN`.
- Post-close tx:
  `0x0441e5cc6413112e790fc4188ba2e5ebbf453c08241e90ef487efdb3391c731f`,
  finalized `MAJORITY_AGREE / FINISHED_WITH_ERROR`; the consensus payload
  decodes to `policy is not active.`

The contract does not create a frontend. It only controls actions that are
actually submitted through RiskBudget; an off-chain agent can still ignore the
protocol or conceal a coordinated strategy.
