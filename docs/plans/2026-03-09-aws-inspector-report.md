# AWS Inspector Report Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a single Python script that fetches AWS Inspector v2 ECR findings and writes a multi-sheet Excel report.

**Architecture:** A single `report.py` file with four logical sections: CLI parsing, AWS data fetching (boto3 paginator), in-memory data processing (age bucketing, severity normalization, grouping), and Excel writing (openpyxl). Tests use `pytest` with `unittest.mock` to patch boto3.

**Tech Stack:** Python 3.9+, `boto3`, `openpyxl`, `pytest`

---

### Task 1: Project Setup

**Files:**
- Create: `requirements.txt`
- Create: `requirements-dev.txt`
- Create: `report.py` (skeleton only)
- Create: `tests/__init__.py`
- Create: `tests/conftest.py`

**Step 1: Create `requirements.txt`**

```
boto3>=1.26.0
openpyxl>=3.1.0
```

**Step 2: Create `requirements-dev.txt`**

```
-r requirements.txt
pytest>=7.0.0
pytest-mock>=3.0.0
```

**Step 3: Create `report.py` skeleton**

```python
#!/usr/bin/env python3
"""AWS Inspector v2 ECR vulnerability report generator."""

import argparse
import sys
from datetime import datetime, timezone


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNTRIAGED"]
AGE_BUCKETS = ["< 30 days", "30-60 days", "60-90 days", "> 90 days"]


def main():
    pass


if __name__ == "__main__":
    main()
```

**Step 4: Create `tests/__init__.py`**

Empty file.

**Step 5: Create `tests/conftest.py`**

```python
import pytest
```

**Step 6: Install dev dependencies**

```bash
pip install -r requirements-dev.txt
```

**Step 7: Verify pytest works**

```bash
pytest tests/ -v
```
Expected: `no tests ran` or `0 passed`

**Step 8: Commit**

```bash
git add requirements.txt requirements-dev.txt report.py tests/
git commit -m "chore: project setup with dependencies and skeleton"
```

---

### Task 2: CLI Argument Parsing

**Files:**
- Create: `tests/test_cli.py`
- Modify: `report.py`

**Step 1: Write failing tests**

Create `tests/test_cli.py`:

```python
import pytest
from report import parse_args


def test_defaults():
    args = parse_args([])
    assert args.output == "inspector_report.xlsx"
    assert args.status == ["ACTIVE"]
    assert args.severity == []
    assert args.repo == []
    assert args.region is None


def test_output_flag():
    args = parse_args(["--output", "my_report.xlsx"])
    assert args.output == "my_report.xlsx"


def test_multiple_severities():
    args = parse_args(["--severity", "CRITICAL", "--severity", "HIGH"])
    assert args.severity == ["CRITICAL", "HIGH"]


def test_multiple_repos():
    args = parse_args(["--repo", "app-a", "--repo", "app-b"])
    assert args.repo == ["app-a", "app-b"]


def test_status_override():
    args = parse_args(["--status", "SUPPRESSED"])
    assert args.status == ["SUPPRESSED"]


def test_region_flag():
    args = parse_args(["--region", "ap-southeast-1"])
    assert args.region == "ap-southeast-1"
```

**Step 2: Run to verify they fail**

```bash
pytest tests/test_cli.py -v
```
Expected: FAIL with `ImportError: cannot import name 'parse_args'`

**Step 3: Implement `parse_args` in `report.py`**

Add after imports:

```python
def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Generate an Excel report from AWS Inspector v2 ECR findings."
    )
    parser.add_argument(
        "--output", default="inspector_report.xlsx",
        help="Output filename (default: inspector_report.xlsx)"
    )
    parser.add_argument(
        "--severity", action="append", default=[],
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"],
        metavar="LEVEL",
        help="Filter by severity (repeatable): CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL"
    )
    parser.add_argument(
        "--repo", action="append", default=[],
        metavar="NAME",
        help="Filter to specific ECR repo name (repeatable)"
    )
    parser.add_argument(
        "--status", action="append", default=None,
        choices=["ACTIVE", "SUPPRESSED", "CLOSED"],
        metavar="STATUS",
        help="Filter by finding status (default: ACTIVE). Options: ACTIVE, SUPPRESSED, CLOSED"
    )
    parser.add_argument(
        "--region", default=None,
        help="AWS region (default: from AWS_DEFAULT_REGION env var)"
    )
    args = parser.parse_args(argv)
    if args.status is None:
        args.status = ["ACTIVE"]
    return args
```

**Step 4: Run tests to verify they pass**

```bash
pytest tests/test_cli.py -v
```
Expected: 6 passed

**Step 5: Commit**

```bash
git add report.py tests/test_cli.py
git commit -m "feat: add CLI argument parsing"
```

---

### Task 3: AWS Data Fetcher

**Files:**
- Create: `tests/test_fetcher.py`
- Modify: `report.py`

**Step 1: Write failing tests**

Create `tests/test_fetcher.py`:

```python
from unittest.mock import MagicMock, patch, call
import pytest
from report import fetch_findings, parse_args


SAMPLE_FINDING = {
    "findingArn": "arn:aws:inspector2:us-east-1:123456789012:finding/abc123",
    "title": "CVE-2023-1234 - libssl",
    "description": "A buffer overflow vulnerability in libssl.",
    "severity": {"label": "HIGH"},
    "firstObservedAt": "2024-01-01T00:00:00Z",
    "status": "ACTIVE",
    "packageVulnerabilityDetails": {
        "cvss": [],
        "referenceUrls": [],
        "vulnerabilityId": "CVE-2023-1234",
    },
    "remediation": {"recommendation": {"text": "Update libssl to version 3.0.9"}},
    "resources": [
        {
            "type": "AWS_ECR_CONTAINER_IMAGE",
            "details": {
                "awsEcrContainerImage": {
                    "repositoryName": "my-app",
                }
            },
        }
    ],
}


@patch("report.boto3.client")
def test_fetch_findings_returns_list(mock_client_factory):
    mock_client = MagicMock()
    mock_client_factory.return_value = mock_client
    paginator = MagicMock()
    mock_client.get_paginator.return_value = paginator
    paginator.paginate.return_value = [{"findings": [SAMPLE_FINDING]}]

    args = parse_args([])
    result = fetch_findings(args)

    assert len(result) == 1
    assert result[0]["findingArn"] == SAMPLE_FINDING["findingArn"]


@patch("report.boto3.client")
def test_fetch_findings_builds_severity_filter(mock_client_factory):
    mock_client = MagicMock()
    mock_client_factory.return_value = mock_client
    paginator = MagicMock()
    mock_client.get_paginator.return_value = paginator
    paginator.paginate.return_value = [{"findings": []}]

    args = parse_args(["--severity", "CRITICAL", "--severity", "HIGH"])
    fetch_findings(args)

    call_kwargs = paginator.paginate.call_args[1]
    severities = call_kwargs["filterCriteria"]["severity"]
    labels = [s["value"] for s in severities]
    assert "CRITICAL" in labels
    assert "HIGH" in labels


@patch("report.boto3.client")
def test_fetch_findings_builds_repo_filter(mock_client_factory):
    mock_client = MagicMock()
    mock_client_factory.return_value = mock_client
    paginator = MagicMock()
    mock_client.get_paginator.return_value = paginator
    paginator.paginate.return_value = [{"findings": []}]

    args = parse_args(["--repo", "my-app"])
    fetch_findings(args)

    call_kwargs = paginator.paginate.call_args[1]
    repos = call_kwargs["filterCriteria"]["ecrImageRepositoryName"]
    assert repos[0]["value"] == "my-app"


@patch("report.boto3.client")
def test_fetch_findings_paginates(mock_client_factory):
    mock_client = MagicMock()
    mock_client_factory.return_value = mock_client
    paginator = MagicMock()
    mock_client.get_paginator.return_value = paginator
    page2_finding = dict(SAMPLE_FINDING, findingArn="arn:aws:inspector2:us-east-1:123:finding/def456")
    paginator.paginate.return_value = [
        {"findings": [SAMPLE_FINDING]},
        {"findings": [page2_finding]},
    ]

    args = parse_args([])
    result = fetch_findings(args)

    assert len(result) == 2
```

**Step 2: Run to verify they fail**

```bash
pytest tests/test_fetcher.py -v
```
Expected: FAIL with `ImportError: cannot import name 'fetch_findings'`

**Step 3: Implement `fetch_findings` in `report.py`**

Add after `parse_args`:

```python
import boto3


def fetch_findings(args):
    """Fetch ECR findings from AWS Inspector v2, returning a flat list."""
    kwargs = {}
    if args.region:
        kwargs["region_name"] = args.region

    client = boto3.client("inspector2", **kwargs)
    paginator = client.get_paginator("list_findings")

    filter_criteria = {
        "findingType": [{"comparison": "EQUALS", "value": "PACKAGE_VULNERABILITY"}],
        "resourceType": [{"comparison": "EQUALS", "value": "AWS_ECR_CONTAINER_IMAGE"}],
        "findingStatus": [
            {"comparison": "EQUALS", "value": s} for s in args.status
        ],
    }

    if args.severity:
        filter_criteria["severity"] = [
            {"comparison": "EQUALS", "value": s} for s in args.severity
        ]

    if args.repo:
        filter_criteria["ecrImageRepositoryName"] = [
            {"comparison": "EQUALS", "value": r} for r in args.repo
        ]

    findings = []
    for page in paginator.paginate(filterCriteria=filter_criteria):
        findings.extend(page.get("findings", []))

    return findings
```

Also move `import boto3` to the top of the file with the other imports.

**Step 4: Run tests to verify they pass**

```bash
pytest tests/test_fetcher.py -v
```
Expected: 4 passed

**Step 5: Commit**

```bash
git add report.py tests/test_fetcher.py
git commit -m "feat: add AWS Inspector data fetcher with pagination and filters"
```

---

### Task 4: Data Processor

**Files:**
- Create: `tests/test_processor.py`
- Modify: `report.py`

The processor normalizes raw findings into a list of dicts with standardized fields, then groups them by repository.

**Step 1: Write failing tests**

Create `tests/test_processor.py`:

```python
from datetime import datetime, timezone, timedelta
import pytest
from report import normalize_findings, age_bucket


def make_finding(severity="HIGH", repo="my-app", days_ago=10, remediation_text=None):
    first_observed = datetime.now(timezone.utc) - timedelta(days=days_ago)
    finding = {
        "title": "CVE-2023-1234 - libssl",
        "description": "A buffer overflow in libssl.",
        "severity": {"label": severity},
        "firstObservedAt": first_observed.isoformat(),
        "remediation": {},
        "resources": [{
            "type": "AWS_ECR_CONTAINER_IMAGE",
            "details": {
                "awsEcrContainerImage": {"repositoryName": repo}
            }
        }],
    }
    if remediation_text:
        finding["remediation"] = {"recommendation": {"text": remediation_text}}
    return finding


# --- age_bucket tests ---

def test_age_bucket_under_30():
    assert age_bucket(29) == "< 30 days"

def test_age_bucket_30_to_60():
    assert age_bucket(30) == "30-60 days"
    assert age_bucket(60) == "30-60 days"

def test_age_bucket_60_to_90():
    assert age_bucket(61) == "60-90 days"
    assert age_bucket(90) == "60-90 days"

def test_age_bucket_over_90():
    assert age_bucket(91) == "> 90 days"


# --- normalize_findings tests ---

def test_normalize_basic_fields():
    raw = [make_finding(severity="HIGH", repo="my-app", days_ago=10)]
    result = normalize_findings(raw)
    assert len(result) == 1
    f = result[0]
    assert f["repo"] == "my-app"
    assert f["severity"] == "HIGH"
    assert f["age_bucket"] == "< 30 days"
    assert f["description"] == "A buffer overflow in libssl."


def test_normalize_informational_becomes_untriaged():
    raw = [make_finding(severity="INFORMATIONAL")]
    result = normalize_findings(raw)
    assert result[0]["severity"] == "UNTRIAGED"


def test_normalize_missing_severity_becomes_untriaged():
    raw = [make_finding()]
    raw[0]["severity"] = {}
    result = normalize_findings(raw)
    assert result[0]["severity"] == "UNTRIAGED"


def test_normalize_remediation_text():
    raw = [make_finding(remediation_text="Update libssl to 3.0.9")]
    result = normalize_findings(raw)
    assert result[0]["remediation"] == "Update libssl to 3.0.9"


def test_normalize_empty_remediation():
    raw = [make_finding()]
    result = normalize_findings(raw)
    assert result[0]["remediation"] == ""


def test_normalize_age_over_90():
    raw = [make_finding(days_ago=100)]
    result = normalize_findings(raw)
    assert result[0]["age_bucket"] == "> 90 days"
```

**Step 2: Run to verify they fail**

```bash
pytest tests/test_processor.py -v
```
Expected: FAIL with `ImportError`

**Step 3: Implement `age_bucket` and `normalize_findings` in `report.py`**

Add after `fetch_findings`:

```python
def age_bucket(days: int) -> str:
    """Return the age bucket label for a given number of days."""
    if days < 30:
        return "< 30 days"
    elif days <= 60:
        return "30-60 days"
    elif days <= 90:
        return "60-90 days"
    else:
        return "> 90 days"


def normalize_findings(raw_findings: list) -> list:
    """Normalize raw Inspector findings into a flat list of dicts."""
    now = datetime.now(timezone.utc)
    results = []
    for f in raw_findings:
        severity_label = f.get("severity", {}).get("label", "")
        if severity_label not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            severity_label = "UNTRIAGED"

        first_observed_str = f.get("firstObservedAt", "")
        try:
            first_observed = datetime.fromisoformat(
                first_observed_str.replace("Z", "+00:00")
            )
        except (ValueError, AttributeError):
            first_observed = now

        days_old = (now - first_observed).days
        remediation = (
            f.get("remediation", {})
             .get("recommendation", {})
             .get("text", "")
        ) or ""

        repo = ""
        for resource in f.get("resources", []):
            details = resource.get("details", {}).get("awsEcrContainerImage", {})
            if details.get("repositoryName"):
                repo = details["repositoryName"]
                break

        results.append({
            "repo": repo,
            "severity": severity_label,
            "description": f.get("description", ""),
            "remediation": remediation,
            "first_observed": first_observed,
            "age_days": days_old,
            "age_bucket": age_bucket(days_old),
        })
    return results
```

**Step 4: Run tests to verify they pass**

```bash
pytest tests/test_processor.py -v
```
Expected: 11 passed

**Step 5: Commit**

```bash
git add report.py tests/test_processor.py
git commit -m "feat: add data normalization and age bucketing"
```

---

### Task 5: Report Data Builders

**Files:**
- Create: `tests/test_builders.py`
- Modify: `report.py`

Three builder functions produce the data structures for each sheet.

**Step 1: Write failing tests**

Create `tests/test_builders.py`:

```python
from datetime import datetime, timezone, timedelta
import pytest
from report import build_severity_summary, build_repo_summary, build_repo_findings


def make_normalized(severity="HIGH", repo="my-app", age_bucket="< 30 days"):
    return {
        "repo": repo,
        "severity": severity,
        "description": "A vulnerability.",
        "remediation": "Update the package.",
        "first_observed": datetime(2024, 6, 1, tzinfo=timezone.utc),
        "age_days": 10,
        "age_bucket": age_bucket,
    }


# --- build_severity_summary ---

def test_severity_summary_counts():
    findings = [
        make_normalized("CRITICAL", age_bucket="< 30 days"),
        make_normalized("CRITICAL", age_bucket="> 90 days"),
        make_normalized("HIGH", age_bucket="30-60 days"),
    ]
    summary = build_severity_summary(findings)
    assert summary["CRITICAL"]["total"] == 2
    assert summary["CRITICAL"]["< 30 days"] == 1
    assert summary["CRITICAL"]["> 90 days"] == 1
    assert summary["HIGH"]["total"] == 1
    assert summary["HIGH"]["30-60 days"] == 1


def test_severity_summary_zeros_missing():
    findings = [make_normalized("HIGH", age_bucket="< 30 days")]
    summary = build_severity_summary(findings)
    assert summary["CRITICAL"]["total"] == 0
    assert summary["HIGH"]["30-60 days"] == 0


# --- build_repo_summary ---

def test_repo_summary_counts():
    findings = [
        make_normalized("CRITICAL", repo="app-a"),
        make_normalized("HIGH", repo="app-a"),
        make_normalized("HIGH", repo="app-b"),
    ]
    summary = build_repo_summary(findings)
    assert summary["app-a"]["CRITICAL"] == 1
    assert summary["app-a"]["HIGH"] == 1
    assert summary["app-a"]["total"] == 2
    assert summary["app-b"]["HIGH"] == 1
    assert summary["app-b"]["total"] == 1


def test_repo_summary_zeros_missing():
    findings = [make_normalized("HIGH", repo="app-a")]
    summary = build_repo_summary(findings)
    assert summary["app-a"]["CRITICAL"] == 0
    assert summary["app-a"]["MEDIUM"] == 0


# --- build_repo_findings ---

def test_repo_findings_sorted_by_severity_then_date():
    findings = [
        {**make_normalized("LOW", "app"), "first_observed": datetime(2024, 3, 1, tzinfo=timezone.utc)},
        {**make_normalized("CRITICAL", "app"), "first_observed": datetime(2024, 6, 1, tzinfo=timezone.utc)},
        {**make_normalized("CRITICAL", "app"), "first_observed": datetime(2024, 1, 1, tzinfo=timezone.utc)},
    ]
    result = build_repo_findings(findings)
    app_findings = result["app"]
    assert app_findings[0]["severity"] == "CRITICAL"
    assert app_findings[0]["first_observed"] == datetime(2024, 1, 1, tzinfo=timezone.utc)
    assert app_findings[1]["severity"] == "CRITICAL"
    assert app_findings[2]["severity"] == "LOW"


def test_repo_findings_groups_by_repo():
    findings = [
        make_normalized("HIGH", repo="app-a"),
        make_normalized("HIGH", repo="app-b"),
        make_normalized("HIGH", repo="app-a"),
    ]
    result = build_repo_findings(findings)
    assert len(result["app-a"]) == 2
    assert len(result["app-b"]) == 1
```

**Step 2: Run to verify they fail**

```bash
pytest tests/test_builders.py -v
```
Expected: FAIL with `ImportError`

**Step 3: Implement builder functions in `report.py`**

Add after `normalize_findings`:

```python
def build_severity_summary(findings: list) -> dict:
    """Build severity-by-age-bucket summary counts."""
    summary = {
        sev: {"total": 0, **{bucket: 0 for bucket in AGE_BUCKETS}}
        for sev in SEVERITY_ORDER
    }
    for f in findings:
        sev = f["severity"]
        summary[sev]["total"] += 1
        summary[sev][f["age_bucket"]] += 1
    return summary


def build_repo_summary(findings: list) -> dict:
    """Build per-repository severity counts."""
    summary = {}
    for f in findings:
        repo = f["repo"]
        if repo not in summary:
            summary[repo] = {sev: 0 for sev in SEVERITY_ORDER}
            summary[repo]["total"] = 0
        summary[repo][f["severity"]] += 1
        summary[repo]["total"] += 1
    return summary


def build_repo_findings(findings: list) -> dict:
    """Group findings by repository, sorted by severity then first observed date."""
    severity_rank = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}
    grouped = {}
    for f in findings:
        repo = f["repo"]
        grouped.setdefault(repo, []).append(f)
    for repo in grouped:
        grouped[repo].sort(
            key=lambda f: (severity_rank.get(f["severity"], 99), f["first_observed"])
        )
    return grouped
```

**Step 4: Run tests to verify they pass**

```bash
pytest tests/test_builders.py -v
```
Expected: 8 passed

**Step 5: Commit**

```bash
git add report.py tests/test_builders.py
git commit -m "feat: add severity summary, repo summary, and per-repo findings builders"
```

---

### Task 6: Excel Writer

**Files:**
- Create: `tests/test_writer.py`
- Modify: `report.py`

**Step 1: Write failing tests**

Create `tests/test_writer.py`:

```python
import os
import tempfile
from datetime import datetime, timezone
import pytest
import openpyxl
from report import write_report, build_severity_summary, build_repo_summary, build_repo_findings


def make_normalized(severity="HIGH", repo="my-app", age_bucket="< 30 days"):
    return {
        "repo": repo,
        "severity": severity,
        "description": "A vulnerability.",
        "remediation": "Update the package.",
        "first_observed": datetime(2024, 6, 1, tzinfo=timezone.utc),
        "age_days": 10,
        "age_bucket": age_bucket,
    }


@pytest.fixture
def sample_findings():
    return [
        make_normalized("CRITICAL", "app-a", "< 30 days"),
        make_normalized("HIGH", "app-a", "> 90 days"),
        make_normalized("HIGH", "app-b", "30-60 days"),
    ]


@pytest.fixture
def report_file(sample_findings, tmp_path):
    output = str(tmp_path / "test_report.xlsx")
    severity_summary = build_severity_summary(sample_findings)
    repo_summary = build_repo_summary(sample_findings)
    repo_findings = build_repo_findings(sample_findings)
    write_report(output, severity_summary, repo_summary, repo_findings)
    return output


def test_creates_file(report_file):
    assert os.path.exists(report_file)


def test_sheet_names(report_file):
    wb = openpyxl.load_workbook(report_file)
    sheets = wb.sheetnames
    assert sheets[0] == "Severity Summary"
    assert sheets[1] == "Repository Summary"
    assert "app-a" in sheets
    assert "app-b" in sheets


def test_severity_summary_headers(report_file):
    wb = openpyxl.load_workbook(report_file)
    ws = wb["Severity Summary"]
    headers = [ws.cell(1, c).value for c in range(1, 7)]
    assert headers[0] == "Severity Level"
    assert headers[1] == "Total"
    assert "< 30 days" in headers


def test_severity_summary_values(report_file):
    wb = openpyxl.load_workbook(report_file)
    ws = wb["Severity Summary"]
    # Find CRITICAL row (row 2)
    row_vals = [ws.cell(2, c).value for c in range(1, 7)]
    assert row_vals[0] == "Critical"
    assert row_vals[1] == 1  # total CRITICAL


def test_repo_summary_headers(report_file):
    wb = openpyxl.load_workbook(report_file)
    ws = wb["Repository Summary"]
    headers = [ws.cell(1, c).value for c in range(1, 8)]
    assert headers[0] == "Amazon ECR Container"
    assert "Critical" in headers
    assert "Total" in headers


def test_per_repo_sheet_headers(report_file):
    wb = openpyxl.load_workbook(report_file)
    ws = wb["app-a"]
    headers = [ws.cell(1, c).value for c in range(1, 6)]
    assert headers == ["S/N", "Description", "Remediation", "Severity", "First Discovered"]


def test_per_repo_sheet_row_count(report_file):
    wb = openpyxl.load_workbook(report_file)
    ws = wb["app-a"]
    # 1 header + 2 findings
    assert ws.max_row == 3


def test_sheet_name_truncated_to_31_chars(tmp_path):
    long_repo = "a" * 40
    findings = [make_normalized("HIGH", long_repo)]
    output = str(tmp_path / "long.xlsx")
    write_report(
        output,
        build_severity_summary(findings),
        build_repo_summary(findings),
        build_repo_findings(findings),
    )
    wb = openpyxl.load_workbook(output)
    for sheet in wb.sheetnames[2:]:
        assert len(sheet) <= 31
```

**Step 2: Run to verify they fail**

```bash
pytest tests/test_writer.py -v
```
Expected: FAIL with `ImportError`

**Step 3: Implement `write_report` in `report.py`**

Add after the builder functions:

```python
import openpyxl
from openpyxl.styles import Font


def _bold(ws, row, col):
    ws.cell(row, col).font = Font(bold=True)


def write_report(
    output_path: str,
    severity_summary: dict,
    repo_summary: dict,
    repo_findings: dict,
):
    """Write all report data to an Excel workbook."""
    wb = openpyxl.Workbook()

    # --- Sheet 1: Severity Summary ---
    ws1 = wb.active
    ws1.title = "Severity Summary"
    headers = ["Severity Level", "Total"] + AGE_BUCKETS
    ws1.append(headers)
    for col in range(1, len(headers) + 1):
        _bold(ws1, 1, col)

    severity_display = {
        "CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium",
        "LOW": "Low", "UNTRIAGED": "Untriaged"
    }
    totals = {bucket: 0 for bucket in ["total"] + AGE_BUCKETS}
    for sev in SEVERITY_ORDER:
        data = severity_summary[sev]
        row = [severity_display[sev], data["total"]] + [data[b] for b in AGE_BUCKETS]
        ws1.append(row)
        totals["total"] += data["total"]
        for b in AGE_BUCKETS:
            totals[b] += data[b]

    total_row = ["Total", totals["total"]] + [totals[b] for b in AGE_BUCKETS]
    ws1.append(total_row)
    for col in range(1, len(headers) + 1):
        _bold(ws1, ws1.max_row, col)

    ws1.freeze_panes = "A2"

    # --- Sheet 2: Repository Summary ---
    ws2 = wb.create_sheet("Repository Summary")
    sev_labels = ["Critical", "High", "Medium", "Low", "Untriaged"]
    sev_keys = SEVERITY_ORDER
    headers2 = ["Amazon ECR Container"] + sev_labels + ["Total"]
    ws2.append(headers2)
    for col in range(1, len(headers2) + 1):
        _bold(ws2, 1, col)

    repo_totals = {key: 0 for key in sev_keys + ["total"]}
    for repo in sorted(repo_summary.keys()):
        data = repo_summary[repo]
        row = [repo] + [data[k] for k in sev_keys] + [data["total"]]
        ws2.append(row)
        for k in sev_keys:
            repo_totals[k] += data[k]
        repo_totals["total"] += data["total"]

    total_row2 = ["Total"] + [repo_totals[k] for k in sev_keys] + [repo_totals["total"]]
    ws2.append(total_row2)
    for col in range(1, len(headers2) + 1):
        _bold(ws2, ws2.max_row, col)

    ws2.freeze_panes = "A2"

    # --- Sheet 3+: Per-repository findings ---
    for repo in sorted(repo_findings.keys()):
        sheet_name = repo[:31]
        ws = wb.create_sheet(sheet_name)
        ws.append(["S/N", "Description", "Remediation", "Severity", "First Discovered"])
        for col in range(1, 6):
            _bold(ws, 1, col)
        for i, f in enumerate(repo_findings[repo], start=1):
            ws.append([
                i,
                f["description"],
                f["remediation"],
                f["severity"].capitalize(),
                f["first_observed"].strftime("%Y-%m-%d"),
            ])
        ws.freeze_panes = "A2"

    wb.save(output_path)
```

Also add `import openpyxl` and `from openpyxl.styles import Font` to the top-level imports.

**Step 4: Run tests to verify they pass**

```bash
pytest tests/test_writer.py -v
```
Expected: 9 passed

**Step 5: Commit**

```bash
git add report.py tests/test_writer.py
git commit -m "feat: add Excel report writer with three sheet types"
```

---

### Task 7: Wire Up `main()` and End-to-End Test

**Files:**
- Create: `tests/test_integration.py`
- Modify: `report.py`

**Step 1: Write failing integration test**

Create `tests/test_integration.py`:

```python
import os
import sys
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone, timedelta
import pytest
import openpyxl
from report import main


def make_raw_finding(severity="HIGH", repo="my-app", days_ago=10):
    first_observed = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return {
        "findingArn": f"arn:aws:inspector2:us-east-1:123:finding/{repo}-{severity}",
        "title": f"CVE-2023-1234 - {repo}",
        "description": f"Vulnerability in {repo}.",
        "severity": {"label": severity},
        "firstObservedAt": first_observed.isoformat(),
        "status": "ACTIVE",
        "remediation": {"recommendation": {"text": f"Fix {repo}"}},
        "resources": [{
            "type": "AWS_ECR_CONTAINER_IMAGE",
            "details": {"awsEcrContainerImage": {"repositoryName": repo}}
        }],
    }


@patch("report.boto3.client")
def test_main_creates_report(mock_client_factory, tmp_path):
    mock_client = MagicMock()
    mock_client_factory.return_value = mock_client
    paginator = MagicMock()
    mock_client.get_paginator.return_value = paginator
    paginator.paginate.return_value = [{
        "findings": [
            make_raw_finding("CRITICAL", "app-a", 5),
            make_raw_finding("HIGH", "app-a", 100),
            make_raw_finding("MEDIUM", "app-b", 45),
        ]
    }]

    output = str(tmp_path / "integration_report.xlsx")
    sys.argv = ["report.py", "--output", output]
    main()

    assert os.path.exists(output)
    wb = openpyxl.load_workbook(output)
    assert "Severity Summary" in wb.sheetnames
    assert "Repository Summary" in wb.sheetnames
    assert "app-a" in wb.sheetnames
    assert "app-b" in wb.sheetnames


@patch("report.boto3.client")
def test_main_empty_findings_creates_report(mock_client_factory, tmp_path):
    mock_client = MagicMock()
    mock_client_factory.return_value = mock_client
    paginator = MagicMock()
    mock_client.get_paginator.return_value = paginator
    paginator.paginate.return_value = [{"findings": []}]

    output = str(tmp_path / "empty_report.xlsx")
    sys.argv = ["report.py", "--output", output]
    main()

    assert os.path.exists(output)
    wb = openpyxl.load_workbook(output)
    assert "Severity Summary" in wb.sheetnames
```

**Step 2: Run to verify it fails**

```bash
pytest tests/test_integration.py -v
```
Expected: FAIL (main() is empty)

**Step 3: Implement `main()` in `report.py`**

Replace the empty `main()`:

```python
def main():
    args = parse_args()
    print("Fetching findings from AWS Inspector v2...")
    raw_findings = fetch_findings(args)
    print(f"Retrieved {len(raw_findings)} findings.")

    findings = normalize_findings(raw_findings)

    severity_summary = build_severity_summary(findings)
    repo_summary = build_repo_summary(findings)
    repo_findings = build_repo_findings(findings)

    write_report(args.output, severity_summary, repo_summary, repo_findings)
    print(f"Report written to: {args.output}")
```

**Step 4: Run all tests to verify everything passes**

```bash
pytest tests/ -v
```
Expected: all tests pass

**Step 5: Commit**

```bash
git add report.py tests/test_integration.py
git commit -m "feat: wire up main() and add end-to-end integration test"
```

---

### Task 8: Final Polish

**Files:**
- Modify: `report.py` (move imports to top, clean up)
- Create: `README.md`

**Step 1: Ensure all imports are at the top of `report.py`**

The final import block should be:

```python
import argparse
import sys
from datetime import datetime, timezone

import boto3
import openpyxl
from openpyxl.styles import Font
```

**Step 2: Run full test suite one final time**

```bash
pytest tests/ -v
```
Expected: all tests pass

**Step 3: Create `README.md`**

```markdown
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
```

**Step 4: Final commit**

```bash
git add report.py README.md
git commit -m "docs: add README and finalize imports"
```
