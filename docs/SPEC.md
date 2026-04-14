# aws-inspector-report — Specification

Functional specification for the aws-inspector-report CLI. Describes *what* the tool does, independent of implementation. For *how* to use it, see the [README](../README.md). For *how* it was built, see [docs/plans/](plans/).

## Purpose

Generate Excel workbooks summarizing ECR container image vulnerability findings from AWS Inspector v2. One run produces up to three reports: a full findings report, a latest-image-only report, and an ECR cleanup report.

## Scope

**In scope**
- AWS Inspector v2 findings for ECR container images.
- Filtering by severity, ECR repository, finding status, AWS region.
- Preservation of historical first-discovered dates across runs via past `-latest.xlsx` reports.

**Out of scope**
- Inspector findings for non-ECR targets (EC2, Lambda).
- Inspector v1.
- Non-Excel output formats.
- Incremental/delta reports (each run is a full snapshot).
- ECR image deletion (cleanup report only generates delete commands).

## Inputs

### AWS APIs

| API call | Purpose |
|---|---|
| `inspector2:ListFindings` | Fetch vulnerability findings |
| `ecr:DescribeImages` | Resolve latest image per repo (for latest-image filtering and cleanup report) |
| `sts:GetCallerIdentity` | Resolve AWS account ID for the default output filename and history lookup |

### CLI

| Flag | Type | Default | Effect |
|---|---|---|---|
| `--output FILE` | string | `{account_id}-inspector-report-{YYMMDD}-{HHmm}.xlsx` | Main report filename. `-latest.xlsx` and `-ecr-cleanup.xlsx` variants are derived from this. |
| `--severity LEVEL` | repeatable | (all) | Filter by severity: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL` |
| `--repo NAME` | repeatable | (all) | Filter by ECR repository name |
| `--status STATUS` | repeatable | `ACTIVE` | Filter by finding status: `ACTIVE`, `SUPPRESSED`, `CLOSED` |
| `--region REGION` | string | `$AWS_DEFAULT_REGION` | AWS region |
| `--history-days DAYS` | int | `60` | Lookback window for inheriting first-discovered dates from past `-latest.xlsx` reports. `0` disables. |
| `--skip-latest` | bool | false | Skip generating the latest-image report |
| `--skip-cleanup` | bool | false | Skip generating the ECR cleanup report |

## Outputs

### 1. Main report — `{account_id}-inspector-report-{YYMMDD}-{HHmm}.xlsx`

All findings matching the filters.

**Sheets**
- `Severity Summary` — counts by severity × age bucket, with Total columns
- `Repository Summary` — counts by repository × severity, with Total columns and a `Total` row
- One sheet per repository named after the repo (truncated to 31 chars; see [Sheet name collisions](#sheet-name-collisions))

**Per-repository sheet columns**
1. S/N — sequential row number
2. Title — Inspector-provided finding title (typically includes CVE ID and package)
3. Remediation — recommended fix text from Inspector, or empty
4. Severity — `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `UNTRIAGED`
5. First Discovered — date string `YYYY-MM-DD`
6. Vulnerability ID — CVE ID (e.g., `CVE-2024-1234`) or empty string

### 2. Latest-image report — `{main}-latest.xlsx`

Same structure as the main report, but scoped to findings whose image is the latest-pushed image per repository.

**Latest-image filtering rules**
- For each repository, the latest image is determined by `imagePushedAt` (DESC) from `ecr:DescribeImages`.
- A finding is included if, and only if, its image digest equals the latest image's digest.
- If the latest image in ECR has no Inspector findings at all (e.g., not yet scanned), the repository is excluded entirely from the latest-image report, even if older images have findings. Rationale: avoids reporting against superseded images.

**First-discovered preservation**
- If `--history-days > 0`, the output directory is scanned for past reports matching the pattern `{account_id}-inspector-report-{YYMMDD}-{HHmm}-latest.xlsx`.
- Only files within the lookback window (default 60 days) whose account ID matches the current run are considered.
- For each past report, per-repo sheets are read and entries keyed on `(repository, title)` are collected. Repository names come from the `Repository Summary` sheet (not sheet names, which may be truncated).
- Merge rule: across all past reports, the **earliest** recorded first-discovered date wins per `(repository, title)` key.
- For each current finding, if a history entry exists with a date earlier than the finding's `firstObservedAt`, the finding's first-discovered date, age in days, and age bucket are recomputed from the historical date.
- The current finding's first-discovered date is never moved forward; only backward.
- Reports generated with a custom `--output` name that does not match the default pattern are not picked up as history.

### 3. ECR cleanup report — `{main}-ecr-cleanup.xlsx`

Identifies non-latest ECR images that can be deleted to reduce Inspector findings churn.

**Sheets**
- `Images to Delete` — one row per non-latest image. Columns: Repository, Tags, Digest, Pushed, Last Pulled, Delete Command.
- `Latest Images` — one row per repository's latest image. Columns: Repository, Tags, Digest, Pushed, Last Pulled. No delete command.

**Delete command format**
```
aws ecr batch-delete-image --region {region} --repository-name {repo} --image-ids imageDigest={digest}
```

## Behavior Rules

### Severity ordering

Fixed order throughout all reports: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNTRIAGED`.

Inspector's `INFORMATIONAL` severity is accepted as a filter input but mapped to `UNTRIAGED` in output.

### Age buckets

Days between run time and `firstObservedAt` (or historical date, if preserved):

- `< 30 days`
- `30-60 days`
- `60-90 days`
- `> 90 days`

### Sheet name collisions

Excel sheet names are limited to 31 characters. Per-repo sheets use the repository name truncated to 31 chars. On collision, a `_2`, `_3`, etc. suffix is appended, with the base further truncated to keep total length ≤ 31.

The write order and collision-resolution algorithm must remain synchronized between writing sheets and reading them back for history lookup — repository names in the `Repository Summary` sheet are the source of truth for reconstructing sheet names during reads.

## Error Handling

| Condition | Behavior |
|---|---|
| `sts:GetCallerIdentity` fails | Account ID resolves to `"unknown"`; run continues |
| `ecr:DescribeImages` fails for a specific repo | That repo's cleanup data is empty; other repos unaffected |
| Past history xlsx file is corrupt or locked | File is skipped with a printed warning; run continues |
| Past history xlsx has no `Repository Summary` sheet | File is skipped; run continues |
| AWS credentials missing/invalid | boto3 raises; run aborts with traceback before any report is written |

## Non-goals

- No incremental reports: each run is a full snapshot.
- No automated ECR deletion: the cleanup report is advisory.
- No deduplication of a single CVE across multiple packages in one finding.
- No matching of findings by CVE ID when the Inspector title changes (today's matching is `(repo, title)` exact). The `Vulnerability ID` column is written for future robustness but is not used in the v1 history match.
