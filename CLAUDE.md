# CloudAudit

Go CLI (module `github.com/Panchal-Sahil/cloudaudit`) that audits an AWS account against the CIS
AWS Foundations Benchmark and outputs a severity-weighted compliance report. Public repo:
https://github.com/Panchal-Sahil/cloudaudit (CI green on `main`).

See `PROJECT.md` for the full rationale, scope constraints, and milestone list — this file is
about how to work on the codebase day to day. See the "Project Session State" section below for
where things currently stand.

## Layout

```
cmd/cloudaudit/          CLI entrypoint (cobra: scan, version)
internal/awsclient/      AWS client setup — default credential chain, sts:GetCallerIdentity preflight
internal/checks/         one file per domain: iam.go, s3.go, network.go, logging.go, encryption.go
                          (+ matching _test.go per file), check.go has the shared Check type/interface
internal/cli/            cobra commands: root.go, scan.go, version.go
internal/report/         score.go (severity-weighted scoring), json.go, terminal.go, report.go
Dockerfile                multi-stage: golang:1.26 -> distroless/static:nonroot
.github/workflows/ci.yml  build-test, lint, docker jobs (all required); optional live-scan job
```

## Checks implemented (14 total)

IAM-1..4, S3-1..3, NET-1..3, LOG-1..2, ENC-1..2 across `internal/checks/{iam,s3,network,logging,encryption}.go`.

## Conventions

- **Narrow-interface + fake pattern**: each check declares a hand-written interface over just the
  specific SDK calls it needs (paginator interfaces where the AWS SDK paginates). Tests use small
  hand-rolled fakes implementing that interface — no mock framework.
- Table-driven tests per check file.
- Evidence strings in findings name the specific offending resource (bucket name, security group
  ID, etc.), not just a generic pass/fail.
- `StatusError` is reserved for failed AWS API calls; `StatusSkip` is for checks that don't apply
  in the account/region being scanned (e.g. a check requiring a resource type that isn't in use).
- Checks that need the current time take a `now time.Time` field, set once in `checks.All()` —
  keeps check logic deterministic and testable.
- Checks run concurrently via a bounded errgroup (`checks.RunAll`).
- Scoring (`internal/report/score.go`): severity-weighted — Critical 10, High 6, Medium 3, Low 1.
  `StatusError` and `StatusSkip` are excluded from the denominator.
- Exit codes: `0` fully compliant, `2` findings present (`cli.ChecksFailedError`), `1` operational
  error (e.g. couldn't reach AWS).
- Commit style: short imperative summary line (e.g. "Reporting: severity-weighted score, JSON
  report, color terminal summary").
- Keep the Dockerfile's `golang:X.Y` base image version in sync with the `go` directive in
  `go.mod` (currently both track 1.26).

## Dev commands

```
go build ./...
go test ./...
golangci-lint run          # config: .golangci.yml (v2 format; errcheck excludes fmt.Fprint*)
```

Toolchain (installed via `dnf` on this machine): Go 1.26.7, golangci-lint 2.11.3.

Docker: `docker build .` — this login session needs `sg docker` to pick up docker-group membership
granted today; a fresh shell/login won't need it going forward.

## Running a real scan

`cloudaudit scan --region <region> --output json --out report.json` (or omit `--output`/`--out`
for the color terminal summary). Uses the standard AWS credential chain — pass credentials via env
vars, not flags, and prefer the `!` bash-prompt-prefix pattern to keep secrets out of the agent's
context when running this interactively.

---

## Project Session State
_Last updated: 2026-08-28_

### Summary
CloudAudit was built from scratch to a complete, working state in a single session on
2026-08-28. It's a Go CLI that runs 14 CIS AWS Foundations Benchmark checks (IAM, S3, network,
logging, encryption) concurrently against a real AWS account and emits a severity-weighted
compliance score as JSON and/or a color terminal summary. All 8 milestones from `PROJECT.md` are
functionally done — CLI scaffold, AWS client, all checks with table-driven tests against
hand-rolled fakes, reporting/scoring, a distroless Docker image (24.1 MB), and a green GitHub
Actions CI pipeline (build-test, lint, docker). The one thing not yet done is a live end-to-end
scan against a real AWS account, because the user doesn't have an AWS account yet — this is
intentionally deferred, not blocked or broken. 7 commits were made and pushed to `main` today;
the working tree is clean.

### Where We Left Off
Everything planned for today is finished and pushed. The next session's first real task is the
deferred live-scan verification once the user has an AWS account (see below) — until then, this
is a stable stopping point. No open bugs, no half-finished code.

### Accomplished
- [x] Milestone 1 — Scaffold: cobra CLI (`scan`, `version`; `--region`/`--output`/`--out` flags), repo structure per `PROJECT.md` architecture
- [x] Milestone 2 — AWS client (`internal/awsclient`): default credential chain, `sts:GetCallerIdentity` preflight
- [x] Milestone 3 — First checks: IAM-1 (root MFA) + S3-1 (public access block) proving the pattern, with parallel runner, terminal output, tests
- [x] Milestone 4 — Remaining checks: IAM-2..4, S3-2..3, NET-1..3, LOG-1..2, ENC-1..2 (14 checks total, `internal/checks/*.go` + tests)
- [x] Milestone 5 — Reporting: severity-weighted score, JSON report, color terminal summary, exit codes (0/1/2) via `cli.ChecksFailedError`
- [x] Milestone 6 — Docker: multi-stage `golang:1.26` -> `distroless/static:nonroot`, 24.1 MB, smoke-tested locally
- [x] Milestone 7 — CI: `.github/workflows/ci.yml` with build-test, lint (golangci-lint-action), docker jobs, all green; optional live-scan job skips silently without AWS secrets
- [x] Milestone 8 — Polish: README with usage, checks table, scoring explanation, mermaid architecture diagram, CI badge (README terminal output is a representative example, not a real run)
- [x] Toolchain setup: Go 1.26.7 and golangci-lint 2.11.3 installed via `dnf`; user added to `docker` group

### Remaining / Next Steps
- [ ] Live end-to-end verification once the user has an AWS account: run `cloudaudit scan` with env-var credentials (use the `!` prompt-prefix pattern to keep secrets out of context), confirm no `StatusError` results
- [ ] Replace the README's sample terminal output with real (redacted) output from that live run
- [ ] Optionally add `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_REGION` as GitHub repo secrets to activate the optional CI live-scan job

### Key Decisions & Context
- No AWS account exists yet for this user — all testing so far is via fakes/mocks in unit tests. This is a deliberate, known gap, not an oversight.
- Narrow hand-written SDK interfaces per check (not one giant AWS client interface) plus small hand-rolled fakes was the chosen test strategy over a mock framework — keeps each check's test surface minimal.
- Scoring intentionally excludes `StatusError`/`StatusSkip` from the denominator so infra hiccups or inapplicable checks don't skew the compliance score.
- Repo is public on GitHub; go.mod pins `go 1.26.7` — keep Dockerfile base image version in lockstep with it.
