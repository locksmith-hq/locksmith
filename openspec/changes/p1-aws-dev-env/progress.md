# Progress: P1 AWS dev environment (append-only)

- 2026-11-19 · planning only: proposal, spec, design and tasks written by a worker; no code. Owner gates: cost brief approval before any apply (task 1.2); task 4.3 touches a protected workflow file and needs a lead PR.

## 2026-11-19 19:36 worker
- Task: 1.1, 1.3 - done (1.2 open: P1-1 not yet in decisions.md; tofu not installed on VM so tasks 2-5 validation needs it)
- Verified: bash scripts/aws-cost-check.sh -> OK ; bash scripts/tree-check.sh -> OK
- Notes for next session: prices are from knowledge, not fetched (aws.amazon.com blocked); owner/lead must verify before P1-1. Task 1.2 stays unticked until approval. Install OpenTofu (and check it is reachable) before tasks 2.1+.

## 2026-11-19 worker
- Task: 2.1, 2.2, 2.3 - done
- Verified: `just aws-validate` -> pass (tofu 1.8.5 fmt+validate x3, 4 policy tests); `just ci` -> exit 0; Sonnet evaluator PASS (planted dir fails tree-check)
- Notes for next session: OpenTofu is not preinstalled; install from the GitHub release zip (v1.8.5, github.com reachable) before `just aws-validate`. Policy is a stdlib Python plan-JSON checker (infra/tofu/policy), not conftest (design decision 7 left the engine open); classic aws_elb not banned. 1.2 gate still open; 3.x next.
