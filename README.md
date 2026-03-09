# aws-inspector-report

Generates an Excel report from AWS Inspector v2 ECR vulnerability findings.

## Setup

```bash
pip install -r requirements.txt
```

## Usage

Set AWS credentials as environment variables:

```bash
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1
```

Run the report:

```bash
python report.py
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--output FILE` | Output filename | `inspector_report.xlsx` |
| `--severity LEVEL` | Filter by severity (repeatable) | all severities |
| `--repo NAME` | Filter by ECR repo name (repeatable) | all repos |
| `--status STATUS` | Finding status filter (repeatable) | `ACTIVE` |
| `--region REGION` | AWS region | `AWS_DEFAULT_REGION` env var |

### Examples

```bash
# All active findings
python report.py

# Only Critical and High findings
python report.py --severity CRITICAL --severity HIGH --output critical.xlsx

# Specific repositories
python report.py --repo my-app --repo another-service
```

## Output

A single Excel workbook with:
- **Sheet 1 — Severity Summary**: Counts by severity × age bracket
- **Sheet 2 — Repository Summary**: Counts by ECR repo × severity
- **Sheet 3+ — Per-repo findings**: Full finding details per repository
