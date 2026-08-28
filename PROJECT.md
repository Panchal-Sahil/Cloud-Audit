# CloudAudit

Go CLI that audits an AWS account against CIS AWS Foundations Benchmark checks and outputs a
scored compliance report.

## What it is

A command-line tool that authenticates to an AWS account via standard credentials, runs a set of
security posture checks against CIS benchmarks, and produces a compliance report with per-check
pass/fail, severity, and a summary score.

Checks cover:
- **IAM** — root account MFA, unused credentials, overly permissive policies, password policy
- **S3** — public bucket policies, unencrypted buckets, access logging
- **Networking** — unrestricted security group rules (0.0.0.0/0 on SSH/RDP), default VPC usage
- **Logging** — CloudTrail enabled and multi-region, CloudTrail log validation, S3 access logging
- **Encryption** — EBS volume encryption, RDS encryption at rest

## Why build this

- CSPM (Cloud Security Posture Management) is what Verafin, Interac CloudOps, Northland, and
  SAP postings describe
- Building the scanner proves understanding of AWS misconfigurations at the API level, not just
  the console
- Go is the lingua franca of cloud tooling (Terraform, Docker, K8s are all Go)
- Closes the AWS gap — all current cloud work is Azure
- Shipping as a Docker image is natural for a CLI tool and demonstrates containerization

## Gaps closed

| Gap | How |
|---|---|
| Docker/containerization | Packaged as a Docker image, multi-stage build |
| CI/CD | GitHub Actions: build, test, lint, scan a test AWS account |
| AWS | Core project — every check hits the AWS API |

## Tech stack

- **Language:** Go
- **AWS:** AWS SDK for Go v2
- **Containers:** Docker (multi-stage build for small image)
- **CI/CD:** GitHub Actions
- **Output:** JSON report + color-coded terminal summary

## Architecture

```
cmd/
  cloudaudit/          <- CLI entrypoint (cobra or bare flags)

internal/
  aws/                 <- AWS client setup, credential handling
  checks/
    iam.go             <- IAM checks (root MFA, unused creds, policies)
    s3.go              <- S3 checks (public access, encryption, logging)
    network.go         <- Security group + VPC checks
    logging.go         <- CloudTrail checks
    encryption.go      <- EBS/RDS encryption checks
  report/
    score.go           <- aggregate pass/fail into a compliance score
    json.go            <- structured JSON output
    terminal.go        <- color-coded terminal output

Dockerfile             <- multi-stage: build in golang, run in scratch/distroless
.github/workflows/     <- CI: build + test + scan
```

## Scope constraints

- Target 12-15 CIS checks, not the full benchmark (82+ checks)
- Read-only AWS API calls only — the tool never modifies resources
- AWS free tier covers all audit API calls
- Support standard AWS credential chain (env vars, shared credentials file, IAM role)
- No need to replicate Prowler or ScoutSuite — pick checks that tell the best story

## Milestones

1. **Scaffold** — repo structure, Go module, cobra CLI skeleton, Dockerfile — DONE (2026-08-28)
2. **AWS client** — credential chain setup, region config, basic connectivity test — DONE (2026-08-28)
3. **First checks** — IAM root MFA + S3 public access (prove the pattern works) — DONE (2026-08-28)
4. **Remaining checks** — network, logging, encryption (parallel development) — DONE (2026-08-28)
5. **Reporting** — JSON output + terminal summary with pass/fail/score — DONE (2026-08-28)
6. **Docker** — multi-stage build, verify the image runs standalone — DONE (2026-08-28)
7. **CI** — GitHub Actions: build, test, lint (golangci-lint), optionally scan a test account — DONE (2026-08-28)
8. **Polish** — README with usage, sample output, architecture diagram — DONE (2026-08-28)

## Status (as of 2026-08-28)

All 8 milestones above are functionally complete. 14 CIS checks are implemented and tested
(IAM-1..4, S3-1..3, NET-1..3, LOG-1..2, ENC-1..2), CI is green on `main`, and the repo is public:
https://github.com/Panchal-Sahil/cloudaudit

**Deferred**: live end-to-end verification against a real AWS account. The user does not yet have
an AWS account. Once available:
- Run `cloudaudit scan` against it and confirm no checks return `StatusError`
- Replace the README's sample terminal output with real (redacted) output
- Optionally add `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_REGION` as GitHub repo
  secrets to activate the optional CI live-scan job

See `CLAUDE.md` for day-to-day dev conventions, layout, and full session history.
