# RiskBudget portal

## Reviewer quick path

1. Read [ARCHITECTURE.md](ARCHITECTURE.md).
2. Inspect [schema/risk_budget.schema.json](schema/risk_budget.schema.json).
3. Run the pinned gates in [README.md](README.md).
4. Review [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md).
5. Check the finalized deployment and live semantic rate-limit smoke below.

## Release evidence

The fields below are completed only from Studio Dev receipts, deployed-source
readback, and live calls after the source freeze.

```text
network: Studio Dev
chain_id: 61997
deployment_status: FINALIZED / Accepted
deployment_tx: 0xc71419f62cf2a97a13c0bc9aa623db15fca2a2133cf6984d083d97dfb08cc498
contract_address: 0x0492f53482231327366312C9A7C38e058Cc20BBB
fee_value: 100000000000010352 wei
source_sha256: 1040fb46fff4beba48c18514888d2aadec46b7d5298ea11091fb007badf41bbc
consensus_status: MAJORITY_AGREE
execution_status: FINISHED_WITH_RETURN
source_readback: genlayer code + gen_getContractCode
source_sha_match: TRUE
live_smoke_status: PASS
live_policy_id: live-risk-20261013; final state CLOSED; action_count=3
live_action_a: AUTHORIZED; tx=0x14a449f5605283c8431d53756279335cecea1917634926b5f3241566d5ba7ff8; charge=9; external=4
live_action_b: AUTHORIZED; retry tx=0x975c3b41f612cdb129af0b193fabc99afa9eae68482b25cf17c45198fb76005f; charge=9; external=4; first equivalent tx was MAJORITY_DISAGREE/Undetermined
live_action_c: DENIED; tx=0xad0112e06d84400d6e08d9f3b174109b0e3922e7c5b5edebf8612f643d2b2299; reason=EXTERNAL_BUDGET_EXCEEDED; charge=9
live_final_external_consumed: 8 / 8
live_denial_accounting_unchanged: TRUE; final policy view reports consumed_external_units=8 after C
live_close_result: FINALIZED / MAJORITY_AGREE; tx=0xf0aba7e2c79a5d4501b9ebb57acff400fb80ecc4f2817a72391d80eea3d19d22; post-close tx finalized with policy is not active.
explorer: https://explorer-studio.genlayer.com/address/0x0492f53482231327366312C9A7C38e058Cc20BBB
```

## Smoke protocol

The controlled smoke creates an `ACTIVE` policy for a distinct agent with
`max_external_units=8` and the fixed `PUBLIC=4` charge. It submits:

1. `Publish the launch announcement publicly.` → `AUTHORIZED`, external
   consumed = 4.
2. `Post the product release update where anyone can see it.` → `AUTHORIZED`,
   external consumed = 8.
3. `Share another public company update with everyone.` → `DENIED`, external
   consumed remains 8.

The policy was then closed by its owner and a post-close authorization attempt
was blocked. The original B attempt finalized as `MAJORITY_DISAGREE /
Undetermined`, so the same packet was retried under a fresh action ID. The
finalized action-view receipts report the two `AUTHORIZED` records and the
`DENIED` record; no evaluator result is inferred from a submitted transaction
alone.

Receipt-backed view transactions:

- policy: `0x9e8bf9e22736ea7c630434999e82560f32a827287d92d841eed8fddcf1abcfc0`
- remaining budget: `0x73e4502c3fc0c2dfa1750becb019c5595d120946faac934647657d27b0d7b141`
- action A: `0xb88c6075d5fc29da249983efe24f708de0a25a26860dd3a1b86e28e6374603b3`
- action B: `0xc6c314d92e6e5de0c2142b30e5b2a89ce3407b0e5f4619018f6beecf004a434e`
- action C: `0x3306f3577434b55c1769b515bab5402892ed02549a879359f68175b1b0f1988a`
