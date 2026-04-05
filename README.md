# aws-inspector-report

Generates Excel reports from AWS Inspector v2 ECR container vulnerability findings.

## Prerequisites

### Python 3.8+

**Windows:**

1. Download the installer from https://www.python.org/downloads/
2. Run the installer — check **"Add Python to PATH"** during setup
3. Verify the installation:
   ```
   python --version
   ```

**macOS:**

```bash
# Using Homebrew
brew install python
python3 --version
```

**Linux (Debian/Ubuntu):**

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv
python3 --version
```

### pip

pip is included with Python 3.4+. Verify it is available:

```bash
pip --version
# or
pip3 --version
```

If pip is missing, install it:

```bash
# Windows / macOS / Linux
python -m ensurepip --upgrade
```

### AWS credentials

You need an AWS IAM identity with permissions for:

- `inspector2:ListFindings` — fetch vulnerability findings
- `ecr:DescribeImages` — query ECR image metadata (used for latest-image filtering and the cleanup report)
- `sts:GetCallerIdentity` — resolve the AWS account ID for the default output filename

Configure credentials via environment variables, AWS CLI profiles, or IAM roles:

```bash
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1
```

Or if using a named profile:

```bash
export AWS_PROFILE=my-profile
export AWS_DEFAULT_REGION=us-east-1
```

## Setup

```bash
# (Optional) Create a virtual environment
python -m venv venv
source venv/bin/activate   # Linux/macOS
venv\Scripts\activate      # Windows

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
python report.py
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--output FILE` | Output filename | `<account_id>-inspector-report-<YYMMDD-HHmm>.xlsx` |
| `--severity LEVEL` | Filter by severity (repeatable): CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL | all severities |
| `--repo NAME` | Filter by ECR repo name (repeatable) | all repos |
| `--status STATUS` | Finding status filter (repeatable): ACTIVE, SUPPRESSED, CLOSED | `ACTIVE` |
| `--region REGION` | AWS region | `AWS_DEFAULT_REGION` env var |
| `--skip-latest` | Skip generating the latest-image-only report | |
| `--skip-cleanup` | Skip generating the ECR image cleanup report | |

### Examples

```bash
# All active findings — generates the full report, latest-image report, and cleanup report
python report.py

# Only Critical and High findings
python report.py --severity CRITICAL --severity HIGH --output critical.xlsx

# Specific repositories
python report.py --repo my-app --repo another-service

# Full report only, no latest-image or cleanup reports
python report.py --skip-latest --skip-cleanup

# Specify a region explicitly
python report.py --region us-west-2
```

## Output

A single run produces up to three Excel workbooks:

### 1. Main report (`*-inspector-report-*.xlsx`)

- **Severity Summary** — vulnerability counts by severity level and age bracket (< 30 days, 30-60, 60-90, > 90 days)
- **Repository Summary** — vulnerability counts by ECR repository and severity level
- **Per-repo sheets** — detailed findings for each repository (title, remediation, severity, first discovered date)

### 2. Latest-image report (`*-inspector-report-*-latest.xlsx`)

Same structure as the main report, but filtered to only include findings from the latest (most recently pushed) image per repository. If the latest image in ECR has no Inspector findings, that repository is excluded entirely.

Skip with `--skip-latest`.

### 3. ECR cleanup report (`*-inspector-report-*-ecr-cleanup.xlsx`)

Identifies old ECR images that can be deleted to keep Inspector findings current:

- **Images to Delete** — lists each non-latest image with repository name, image tags, image digest, date pushed, date last pulled, and the `aws ecr batch-delete-image` CLI command to delete it
- **Latest Images** — the latest image per repository (no delete command)

Skip with `--skip-cleanup`.

## Running tests

```bash
pip install pytest pytest-mock
python -m pytest tests/ -v
```
