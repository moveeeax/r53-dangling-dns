# r53-dangling-dns

[![ci](https://github.com/moveeeax/r53-dangling-dns/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/r53-dangling-dns/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/go-1.22%2B-00ADD8?logo=go)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Find Route53 records that point at AWS resources you already deleted — before an
attacker re-provisions the endpoint and serves content under your subdomain.

A deleted ELB, torn-down CloudFront distribution, released Elastic IP, or emptied
S3 website bucket often leaves its DNS record behind. That record is a
**subdomain-takeover** waiting to happen. `r53-dangling-dns` walks your hosted
zones, cross-checks every ALIAS/CNAME/A target against your **live AWS
inventory**, and flags the orphans.

## How it works

1. **List records.** Page through every hosted zone (or one `--zone`) and flatten
   each A/AAAA/CNAME/ALIAS record set to individual targets.
2. **Build inventory.** Read-only `Describe`/`List` calls collect the DNS names of
   live load balancers (ALB/NLB + classic), CloudFront distributions, S3 buckets,
   and account-owned public IPs (EIPs + instance IPs).
3. **Classify.** Each target is matched to the AWS service it belongs to and
   checked against inventory:
   - `dangling` — the backing resource is confirmed gone (takeover-prone).
   - `suspicious` — an endpoint we can't confirm (e.g. an A record to an IP that
     isn't in your account); worth a human look.
   - `ok` — the backing resource exists.
4. **Report & gate.** Emit a table, JSON, or SARIF, and optionally exit non-zero
   with `--fail-on` so a pipeline blocks on new dangling records.

Everything is read-only. The exact permissions are in
[`docs/iam-policy.json`](docs/iam-policy.json).

## Install

```sh
go install github.com/moveeeax/r53-dangling-dns@latest
```

Or build from source: `go build -o r53-dangling-dns .`

## Usage

```sh
# Scan every hosted zone in the current account
r53-dangling-dns scan

# Limit to one zone and probe live endpoints for unclaimed fingerprints
r53-dangling-dns scan --zone example.com --probe

# JSON for tooling
r53-dangling-dns scan --output json > findings.json

# Fail CI when any dangling record is found, emit SARIF
r53-dangling-dns scan --output sarif --fail-on dangling > r53.sarif
```

Example table output:

```
SEVERITY    RECORD              KIND  TARGET / REASON
dangling    docs.example.com    s3    deleted-docs.s3-website-us-east-1.amazonaws.com — no S3 bucket named deleted-docs in the account
dangling    legacy.example.com  elb   old-lb-9.us-east-1.elb.amazonaws.com — no load balancer with this DNS name in the account
suspicious  vpn.example.com     ip    198.51.100.7 — address not found among account EIPs/instance IPs; verify it is still yours
ok          app.example.com     elb   prod-alb-1.us-east-1.elb.amazonaws.com — load balancer exists

5 record(s): 2 dangling, 1 suspicious, 2 ok
```

Sample [`examples/findings.json`](examples/findings.json) and
[`examples/findings.sarif`](examples/findings.sarif) show the machine-readable
formats. Upload the SARIF to GitHub code scanning to see findings inline.

## Flags

| Flag | Description |
| --- | --- |
| `--zone` | Limit the scan to a single hosted zone name. |
| `--region` | AWS region (defaults to the resolved SDK region). |
| `-o, --output` | `table` (default), `json`, or `sarif`. |
| `--fail-on` | Exit code `2` when a finding reaches `dangling`, `suspicious`, or `ok`. |
| `--probe` | Resolve records live and fingerprint unclaimed endpoints (escalates suspicious → dangling). |

## Credentials

Uses the standard AWS SDK credential chain (env vars, shared config, IAM role).
Attach the read-only policy in `docs/iam-policy.json`.

## License

MIT — see [LICENSE](LICENSE).
