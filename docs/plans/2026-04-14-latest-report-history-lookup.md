# Latest-Report History Lookup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve true "first discovered" dates on the latest-image report by reading past `-latest.xlsx` reports from the output directory, so that dates don't reset each time a new image is pushed to ECR.

**Architecture:** On each run, before writing the latest-image report, scan the output directory for past `<account-id>-inspector-report-*-latest.xlsx` files within a configurable window (default 60 days). Read each file's `Repository Summary` to learn full repo names, then read per-repo sheets to extract `(repo, title) → first_discovered`. Merge those dates with the current run's data, always taking the minimum. Also add a `Vulnerability ID` column to per-repo sheets for future-proofing.

**Tech Stack:** Python 3.8+, openpyxl, pytest, pytest-mock. No new dependencies.

**Key design constraints (from user):**
- Match findings by exact `Title` column (not by `vulnerabilityId` — legacy reports don't have it).
- Read repo names from the `Repository Summary` sheet (not by modifying per-repo sheets) to resolve Excel's 31-char sheet-name truncation.
- Minimize file modifications — single-file changes to `report.py` plus tests.
- `Vulnerability ID` column added as *last* column on per-repo sheets for future robustness.
- History applied to **latest-image report only** — the main report's per-image `firstObservedAt` stays as-is.

---

## File Structure

**Modify:**
- `report.py` — add history functions, add `--history-days` flag, wire into `main()`, extend writer with `Vulnerability ID` column
- `tests/test_writer.py` — update tests for the new column
- `README.md` — document new flag and behavior

**Create:**
- `tests/test_history.py` — unit tests for filename parsing, history reading, date merging

---

## Task 1: Add `Vulnerability ID` column to per-repo sheets

**Files:**
- Modify: `report.py:224-286` (`normalize_findings`)
- Modify: `report.py:407-417` (`write_report` per-repo section)
- Modify: `tests/test_writer.py:80-91` (update header and row count tests)

### Step 1.1: Write failing test for the new column

- [ ] **Edit** `tests/test_writer.py` — update the header test to expect 6 columns ending with `Vulnerability ID`:

```python
def test_per_repo_sheet_headers(report_file):
    wb = openpyxl.load_workbook(report_file)
    ws = wb["app-a"]
    headers = [ws.cell(1, c).value for c in range(1, 7)]
    assert headers == ["S/N", "Title", "Remediation", "Severity", "First Discovered", "Vulnerability ID"]
```

- [ ] **Edit** `tests/test_writer.py:9-18` — add `vulnerability_id` to the fixture:

```python
def make_normalized(severity="HIGH", repo="my-app", age_bucket="< 30 days", vuln_id="CVE-2024-0001"):
    return {
        "repo": repo,
        "severity": severity,
        "title": "A vulnerability.",
        "remediation": "Update the package.",
        "first_observed": datetime(2024, 6, 1, tzinfo=timezone.utc),
        "age_days": 10,
        "age_bucket": age_bucket,
        "vulnerability_id": vuln_id,
    }
```

- [ ] **Edit** `tests/test_writer.py:109-118` — update the unknown-repo finding dict to include `"vulnerability_id": ""`:

```python
findings = [{
    "repo": "(unknown)",
    "severity": "HIGH",
    "title": "A vulnerability.",
    "remediation": "",
    "first_observed": datetime(2024, 6, 1, tzinfo=timezone.utc),
    "age_days": 10,
    "age_bucket": "< 30 days",
    "vulnerability_id": "",
}]
```

- [ ] **Add** a new test after `test_per_repo_sheet_headers`:

```python
def test_per_repo_sheet_includes_vuln_id(report_file):
    wb = openpyxl.load_workbook(report_file)
    ws = wb["app-a"]
    assert ws.cell(2, 6).value == "CVE-2024-0001"
```

### Step 1.2: Run tests to verify they fail

Run: `python -m pytest tests/test_writer.py -v`
Expected: FAIL with assertion errors (extra column not yet written, key missing in normalized dict).

### Step 1.3: Extract `vulnerability_id` in `normalize_findings`

- [ ] **Edit** `report.py:277-285` — add `vulnerability_id` to the normalized dict (inside the `results.append({...})` block):

```python
        vulnerability_id = (
            f.get("packageVulnerabilityDetails", {}).get("vulnerabilityId", "") or ""
        )

        results.append({
            "repo": repo,
            "severity": severity_label,
            "title": f.get("title", ""),
            "remediation": remediation,
            "first_observed": first_observed,
            "age_days": days_old,
            "age_bucket": age_bucket(days_old),
            "vulnerability_id": vulnerability_id,
        })
```

### Step 1.4: Write the column in `write_report`

- [ ] **Edit** `report.py:407-418` — update the per-repo sheet writing:

```python
        ws.append(["S/N", "Title", "Remediation", "Severity", "First Discovered", "Vulnerability ID"])
        for col in range(1, 7):
            _bold(ws, 1, col)
        for i, f in enumerate(repo_findings[repo], start=1):
            ws.append([
                i,
                f["title"],
                f["remediation"],
                f["severity"].capitalize(),
                f["first_observed"].strftime("%Y-%m-%d"),
                f.get("vulnerability_id", ""),
            ])
        ws.freeze_panes = "A2"
```

### Step 1.5: Run tests to verify they pass

Run: `python -m pytest tests/test_writer.py -v`
Expected: PASS (all writer tests green).

Run: `python -m pytest tests/ -v`
Expected: PASS (no other tests regressed — processor/integration tests may need `vulnerability_id` key; check and add it to any other test fixtures that construct normalized finding dicts directly).

- [ ] **If other tests fail** due to missing `vulnerability_id` key, add `"vulnerability_id": ""` to each offending fixture. Run again until all tests pass.

### Step 1.6: Commit

```bash
git add report.py tests/test_writer.py tests/
git commit -m "feat: add Vulnerability ID column to per-repo sheets"
```

---

## Task 2: Parse and filter historical report filenames

**Files:**
- Modify: `report.py` (add new functions near top of file, after `AGE_BUCKETS`)
- Create: `tests/test_history.py`

### Step 2.1: Write failing tests for filename parsing

- [ ] **Create** `tests/test_history.py`:

```python
import os
from datetime import datetime, timezone, timedelta
import pytest
from report import parse_report_filename, find_history_reports


NOW = datetime(2026, 4, 14, 15, 0, tzinfo=timezone.utc)


def test_parse_report_filename_valid():
    result = parse_report_filename("111222333444-inspector-report-260309-1430-latest.xlsx")
    assert result == ("111222333444", datetime(2026, 3, 9, 14, 30, tzinfo=timezone.utc))


def test_parse_report_filename_with_dir_prefix():
    result = parse_report_filename("/tmp/out/555-inspector-report-251201-0900-latest.xlsx")
    assert result == ("555", datetime(2025, 12, 1, 9, 0, tzinfo=timezone.utc))


def test_parse_report_filename_non_latest_returns_none():
    assert parse_report_filename("111-inspector-report-260309-1430.xlsx") is None


def test_parse_report_filename_non_matching_returns_none():
    assert parse_report_filename("something-else.xlsx") is None
    assert parse_report_filename("111-inspector-report-260309-1430-ecr-cleanup.xlsx") is None


def test_find_history_reports_filters_by_account(tmp_path):
    (tmp_path / "111-inspector-report-260310-1000-latest.xlsx").write_bytes(b"")
    (tmp_path / "999-inspector-report-260310-1000-latest.xlsx").write_bytes(b"")
    result = find_history_reports(str(tmp_path), "111", max_age_days=60, now=NOW)
    assert len(result) == 1
    assert result[0].endswith("111-inspector-report-260310-1000-latest.xlsx")


def test_find_history_reports_filters_by_age(tmp_path):
    (tmp_path / "111-inspector-report-260410-1000-latest.xlsx").write_bytes(b"")  # 4 days old
    (tmp_path / "111-inspector-report-260101-1000-latest.xlsx").write_bytes(b"")  # >90 days old
    result = find_history_reports(str(tmp_path), "111", max_age_days=60, now=NOW)
    assert len(result) == 1
    assert "260410" in result[0]


def test_find_history_reports_excludes_non_latest(tmp_path):
    (tmp_path / "111-inspector-report-260410-1000-latest.xlsx").write_bytes(b"")
    (tmp_path / "111-inspector-report-260410-1000.xlsx").write_bytes(b"")
    (tmp_path / "111-inspector-report-260410-1000-ecr-cleanup.xlsx").write_bytes(b"")
    result = find_history_reports(str(tmp_path), "111", max_age_days=60, now=NOW)
    assert len(result) == 1
    assert result[0].endswith("latest.xlsx")


def test_find_history_reports_empty_dir(tmp_path):
    assert find_history_reports(str(tmp_path), "111", max_age_days=60, now=NOW) == []


def test_find_history_reports_missing_dir():
    assert find_history_reports("/nonexistent/path/xyz", "111", max_age_days=60, now=NOW) == []
```

### Step 2.2: Run tests to verify they fail

Run: `python -m pytest tests/test_history.py -v`
Expected: FAIL with `ImportError: cannot import name 'parse_report_filename'`.

### Step 2.3: Implement `parse_report_filename` and `find_history_reports`

- [ ] **Edit** `report.py` — add these imports at the top (after the existing `from datetime import ...` line):

```python
import os
import re
from datetime import datetime, timezone, timedelta
```

(Merge with existing imports — `os` and `re` are new; `timedelta` is new.)

- [ ] **Edit** `report.py` — add these functions right after the `AGE_BUCKETS` constant (around line 14):

```python
_LATEST_REPORT_RE = re.compile(
    r"^(?P<account>\d+)-inspector-report-(?P<date>\d{6})-(?P<time>\d{4})-latest\.xlsx$"
)


def parse_report_filename(path):
    """Parse a latest-report filename into (account_id, timestamp_utc).

    Returns None if the filename does not match the pattern.
    """
    basename = os.path.basename(path)
    m = _LATEST_REPORT_RE.match(basename)
    if not m:
        return None
    try:
        ts = datetime.strptime(m.group("date") + m.group("time"), "%y%m%d%H%M")
        ts = ts.replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return (m.group("account"), ts)


def find_history_reports(search_dir, account_id, max_age_days, now=None):
    """Return sorted list of -latest.xlsx report paths matching account_id within max_age_days."""
    if not os.path.isdir(search_dir):
        return []
    if now is None:
        now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=max_age_days)
    results = []
    for name in os.listdir(search_dir):
        parsed = parse_report_filename(name)
        if parsed is None:
            continue
        acct, ts = parsed
        if acct != account_id:
            continue
        if ts < cutoff:
            continue
        results.append(os.path.join(search_dir, name))
    results.sort()
    return results
```

### Step 2.4: Run tests to verify they pass

Run: `python -m pytest tests/test_history.py -v`
Expected: PASS (all 8 tests green).

### Step 2.5: Commit

```bash
git add report.py tests/test_history.py
git commit -m "feat: parse and filter historical latest-report filenames"
```

---

## Task 3: Read historical first-discovered dates from a single report

**Files:**
- Modify: `report.py` (add `read_history_from_report`)
- Modify: `tests/test_history.py` (add tests)

### Step 3.1: Write failing tests for reading history from a report file

- [ ] **Edit** `tests/test_history.py` — append these imports and tests at the end:

```python
from datetime import datetime, timezone
from report import (
    read_history_from_report,
    write_report,
    build_severity_summary,
    build_repo_summary,
    build_repo_findings,
)


def _finding(repo, title, date, vuln="CVE-2024-0001"):
    return {
        "repo": repo,
        "severity": "HIGH",
        "title": title,
        "remediation": "fix",
        "first_observed": date,
        "age_days": 30,
        "age_bucket": "30-60 days",
        "vulnerability_id": vuln,
    }


def _write_fixture_report(path, findings):
    write_report(
        path,
        build_severity_summary(findings),
        build_repo_summary(findings),
        build_repo_findings(findings),
    )


def test_read_history_from_report_basic(tmp_path):
    date1 = datetime(2025, 8, 1, tzinfo=timezone.utc)
    date2 = datetime(2025, 9, 15, tzinfo=timezone.utc)
    findings = [
        _finding("app-a", "CVE-A - openssl", date1),
        _finding("app-b", "CVE-B - python", date2),
    ]
    path = str(tmp_path / "111-inspector-report-250915-1000-latest.xlsx")
    _write_fixture_report(path, findings)

    history = read_history_from_report(path)
    assert history[("app-a", "CVE-A - openssl")] == date1
    assert history[("app-b", "CVE-B - python")] == date2


def test_read_history_from_report_handles_truncated_repo_name(tmp_path):
    # Two repos that both truncate to same 31-char prefix
    repo_long_a = "a" * 32 + "X"
    repo_long_b = "a" * 32 + "Y"
    date = datetime(2025, 10, 1, tzinfo=timezone.utc)
    findings = [
        _finding(repo_long_a, "Title A", date),
        _finding(repo_long_b, "Title B", date),
    ]
    path = str(tmp_path / "111-inspector-report-251001-1000-latest.xlsx")
    _write_fixture_report(path, findings)

    history = read_history_from_report(path)
    # Full repo names must be used as keys, not truncated sheet names
    assert (repo_long_a, "Title A") in history
    assert (repo_long_b, "Title B") in history


def test_read_history_from_report_missing_file_returns_empty(tmp_path):
    history = read_history_from_report(str(tmp_path / "nonexistent.xlsx"))
    assert history == {}


def test_read_history_from_report_skips_total_row(tmp_path):
    date = datetime(2025, 10, 1, tzinfo=timezone.utc)
    findings = [_finding("app-a", "T1", date)]
    path = str(tmp_path / "111-inspector-report-251001-1000-latest.xlsx")
    _write_fixture_report(path, findings)

    history = read_history_from_report(path)
    # Confirm no entry keyed by "Total" leaked in
    assert not any(k[0] == "Total" for k in history)
```

### Step 3.2: Run tests to verify they fail

Run: `python -m pytest tests/test_history.py -v`
Expected: FAIL with `ImportError: cannot import name 'read_history_from_report'`.

### Step 3.3: Implement `read_history_from_report`

- [ ] **Edit** `report.py` — add these functions after `find_history_reports` (reuse the truncation algorithm from `write_report`):

```python
def _derive_sheet_name_for_repo(repo, used_names):
    """Replicate the sheet-name truncation/collision logic from write_report."""
    base = repo[:31]
    sheet_name = base
    counter = 2
    while sheet_name in used_names:
        suffix = f"_{counter}"
        sheet_name = base[:31 - len(suffix)] + suffix
        counter += 1
    return sheet_name


def _repos_in_order_from_summary(workbook):
    """Read full repo names from the Repository Summary sheet in written order."""
    if "Repository Summary" not in workbook.sheetnames:
        return []
    ws = workbook["Repository Summary"]
    repos = []
    for row in range(2, ws.max_row + 1):
        name = ws.cell(row, 1).value
        if name is None or name == "Total":
            continue
        repos.append(str(name))
    return repos


def read_history_from_report(path):
    """Read {(repo, title): first_discovered_utc} from a past latest-report xlsx.

    Uses the Repository Summary sheet to learn full repo names, then reproduces
    write_report's sheet-name truncation to locate each per-repo sheet.  Returns
    an empty dict on any error (missing file, unreadable, unexpected format).
    """
    import openpyxl  # local import keeps top of file tidy; openpyxl is already a dep
    try:
        wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    except Exception:
        return {}

    result = {}
    try:
        repos = _repos_in_order_from_summary(wb)
        used_sheet_names = set()
        for repo in repos:
            sheet_name = _derive_sheet_name_for_repo(repo, used_sheet_names)
            used_sheet_names.add(sheet_name)
            if sheet_name not in wb.sheetnames:
                continue
            ws = wb[sheet_name]
            # Find column indices by header name (resilient to new columns)
            headers = {ws.cell(1, c).value: c for c in range(1, ws.max_column + 1)}
            title_col = headers.get("Title")
            date_col = headers.get("First Discovered")
            if not title_col or not date_col:
                continue
            for row in range(2, ws.max_row + 1):
                title = ws.cell(row, title_col).value
                date_raw = ws.cell(row, date_col).value
                if not title or not date_raw:
                    continue
                parsed_date = _parse_history_date(date_raw)
                if parsed_date is None:
                    continue
                key = (repo, str(title))
                if key not in result or parsed_date < result[key]:
                    result[key] = parsed_date
    finally:
        wb.close()
    return result


def _parse_history_date(value):
    """Parse a date cell from a past report. Returns UTC datetime or None."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None
```

### Step 3.4: Run tests to verify they pass

Run: `python -m pytest tests/test_history.py -v`
Expected: PASS (all history tests green).

Run: `python -m pytest tests/ -v`
Expected: PASS (no regressions).

### Step 3.5: Commit

```bash
git add report.py tests/test_history.py
git commit -m "feat: read historical first-discovered dates from past reports"
```

---

## Task 4: Merge and apply history to latest-report findings

**Files:**
- Modify: `report.py` (add `load_history` and `apply_history`)
- Modify: `tests/test_history.py` (add tests)

### Step 4.1: Write failing tests for merging and applying history

- [ ] **Edit** `tests/test_history.py` — append these tests:

```python
from report import load_history, apply_history, age_bucket


def test_load_history_merges_across_reports_taking_earliest(tmp_path):
    earlier = datetime(2025, 6, 1, tzinfo=timezone.utc)
    later = datetime(2025, 9, 1, tzinfo=timezone.utc)

    # Newer report has a later date for the same finding
    findings1 = [_finding("app-a", "CVE-A", later)]
    _write_fixture_report(str(tmp_path / "111-inspector-report-250901-1000-latest.xlsx"), findings1)

    # Older report has the true earliest date
    findings2 = [_finding("app-a", "CVE-A", earlier)]
    _write_fixture_report(str(tmp_path / "111-inspector-report-250601-1000-latest.xlsx"), findings2)

    now = datetime(2025, 9, 2, tzinfo=timezone.utc)
    history = load_history(str(tmp_path), "111", max_age_days=365, now=now)
    assert history[("app-a", "CVE-A")] == earlier


def test_load_history_returns_empty_when_no_reports(tmp_path):
    history = load_history(str(tmp_path), "111", max_age_days=60)
    assert history == {}


def test_apply_history_overrides_with_earlier_date():
    now = datetime(2026, 4, 14, tzinfo=timezone.utc)
    current_date = datetime(2026, 3, 1, tzinfo=timezone.utc)
    historical = datetime(2025, 1, 1, tzinfo=timezone.utc)

    findings = [{
        "repo": "app-a",
        "severity": "HIGH",
        "title": "CVE-A",
        "remediation": "",
        "first_observed": current_date,
        "age_days": (now - current_date).days,
        "age_bucket": age_bucket((now - current_date).days),
        "vulnerability_id": "CVE-2024-0001",
    }]
    history = {("app-a", "CVE-A"): historical}

    matched = apply_history(findings, history, now=now)
    assert matched == 1
    assert findings[0]["first_observed"] == historical
    assert findings[0]["age_days"] == (now - historical).days
    assert findings[0]["age_bucket"] == "> 90 days"


def test_apply_history_ignores_later_date():
    now = datetime(2026, 4, 14, tzinfo=timezone.utc)
    current_date = datetime(2025, 1, 1, tzinfo=timezone.utc)
    historical = datetime(2026, 3, 1, tzinfo=timezone.utc)  # later than current

    findings = [{
        "repo": "app-a", "severity": "HIGH", "title": "CVE-A", "remediation": "",
        "first_observed": current_date,
        "age_days": (now - current_date).days,
        "age_bucket": age_bucket((now - current_date).days),
        "vulnerability_id": "",
    }]
    history = {("app-a", "CVE-A"): historical}

    matched = apply_history(findings, history, now=now)
    assert matched == 0
    assert findings[0]["first_observed"] == current_date


def test_apply_history_no_match_leaves_finding_unchanged():
    now = datetime(2026, 4, 14, tzinfo=timezone.utc)
    current_date = datetime(2026, 3, 1, tzinfo=timezone.utc)
    findings = [{
        "repo": "app-a", "severity": "HIGH", "title": "CVE-A", "remediation": "",
        "first_observed": current_date,
        "age_days": (now - current_date).days,
        "age_bucket": "30-60 days",
        "vulnerability_id": "",
    }]
    history = {("other-repo", "other-title"): datetime(2024, 1, 1, tzinfo=timezone.utc)}

    matched = apply_history(findings, history, now=now)
    assert matched == 0
    assert findings[0]["first_observed"] == current_date
```

### Step 4.2: Run tests to verify they fail

Run: `python -m pytest tests/test_history.py -v`
Expected: FAIL with `ImportError: cannot import name 'load_history'`.

### Step 4.3: Implement `load_history` and `apply_history`

- [ ] **Edit** `report.py` — add these functions after `read_history_from_report`:

```python
def load_history(search_dir, account_id, max_age_days, now=None):
    """Merge historical first-discovered dates across all qualifying past reports.

    For the same (repo, title) present in multiple past reports, the earliest
    date wins.  Failures reading any single report are logged and skipped.
    """
    merged = {}
    paths = find_history_reports(search_dir, account_id, max_age_days, now=now)
    for path in paths:
        try:
            per_report = read_history_from_report(path)
        except Exception as e:
            print(f"Warning: failed to read history from {path}: {e}")
            continue
        for key, date in per_report.items():
            if key not in merged or date < merged[key]:
                merged[key] = date
    return merged


def apply_history(findings, history, now=None):
    """Override first_observed with earlier historical date when available.

    Mutates findings in place; recomputes age_days and age_bucket when a date
    is replaced.  Returns the count of findings updated.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    updated = 0
    for f in findings:
        key = (f["repo"], f["title"])
        hist_date = history.get(key)
        if hist_date is not None and hist_date < f["first_observed"]:
            f["first_observed"] = hist_date
            f["age_days"] = (now - hist_date).days
            f["age_bucket"] = age_bucket(f["age_days"])
            updated += 1
    return updated
```

### Step 4.4: Run tests to verify they pass

Run: `python -m pytest tests/test_history.py -v`
Expected: PASS (all history tests green).

Run: `python -m pytest tests/ -v`
Expected: PASS.

### Step 4.5: Commit

```bash
git add report.py tests/test_history.py
git commit -m "feat: merge and apply historical first-discovered dates"
```

---

## Task 5: Wire history lookup into `main()` with `--history-days` flag

**Files:**
- Modify: `report.py:17-57` (`parse_args`)
- Modify: `report.py:478-531` (`main`)
- Modify: `tests/test_cli.py` (add flag test)
- Modify: `tests/test_integration.py` (add end-to-end test)

### Step 5.1: Write failing test for the CLI flag

- [ ] **Read** `tests/test_cli.py` first to understand the existing pattern:

Run: `python -m pytest tests/test_cli.py -v` (verify baseline passes)

- [ ] **Edit** `tests/test_cli.py` — add a test for the new flag (append to end):

```python
def test_history_days_default_is_60():
    from report import parse_args
    args = parse_args([])
    assert args.history_days == 60


def test_history_days_accepts_zero():
    from report import parse_args
    args = parse_args(["--history-days", "0"])
    assert args.history_days == 0


def test_history_days_custom_value():
    from report import parse_args
    args = parse_args(["--history-days", "90"])
    assert args.history_days == 90
```

### Step 5.2: Run CLI tests to verify they fail

Run: `python -m pytest tests/test_cli.py -v`
Expected: FAIL (flag not defined yet).

### Step 5.3: Add the CLI flag

- [ ] **Edit** `report.py:17-57` — add `--history-days` to `parse_args` (insert right before `args = parser.parse_args(argv)`):

```python
    parser.add_argument(
        "--history-days", type=int, default=60, metavar="DAYS",
        help="Look back N days of past -latest.xlsx reports to preserve first-discovered dates. "
             "Set to 0 to disable. Only applies to the latest-image report. Default: 60"
    )
```

### Step 5.4: Run CLI tests to verify they pass

Run: `python -m pytest tests/test_cli.py -v`
Expected: PASS.

### Step 5.5: Wire history lookup into `main()`

- [ ] **Edit** `report.py:478-531` — rewrite `main()`:

```python
def main():
    args = parse_args()

    account_id = get_account_id(args.region)

    if args.output is None:
        timestamp = datetime.now().strftime("%y%m%d-%H%M")
        args.output = f"{account_id}-inspector-report-{timestamp}.xlsx"

    print("Fetching findings from AWS Inspector v2...")
    raw_findings = fetch_findings(args)
    print(f"Retrieved {len(raw_findings)} findings.")

    findings = normalize_findings(raw_findings)

    severity_summary = build_severity_summary(findings)
    repo_summary = build_repo_summary(findings)
    repo_findings = build_repo_findings(findings)

    write_report(args.output, severity_summary, repo_summary, repo_findings)
    print(f"Report written to: {args.output}")

    need_ecr = not args.skip_latest or not args.skip_cleanup
    ecr_images = {}
    ecr_latest = {}
    if need_ecr:
        repos_in_findings = set()
        for f in raw_findings:
            details = _get_image_details(f)
            repo = details.get("repositoryName")
            if repo:
                repos_in_findings.add(repo)
        print("Querying ECR for image details...")
        ecr_images = fetch_ecr_images(repos_in_findings, args.region)
        ecr_latest = latest_digests_from_images(ecr_images)

    if not args.skip_latest:
        latest_raw = filter_latest_image_findings(raw_findings, ecr_latest)
        print(f"Filtered to {len(latest_raw)} findings for latest images.")
        latest_findings = normalize_findings(latest_raw)

        if args.history_days > 0:
            history_dir = os.path.dirname(os.path.abspath(args.output)) or "."
            history = load_history(history_dir, account_id, args.history_days)
            if history:
                matched = apply_history(latest_findings, history)
                print(f"Applied {matched} first-discovered dates from {len(history)} historical entries.")

        latest_severity = build_severity_summary(latest_findings)
        latest_repo = build_repo_summary(latest_findings)
        latest_repo_findings = build_repo_findings(latest_findings)
        latest_output = args.output.replace(".xlsx", "-latest.xlsx")
        write_report(latest_output, latest_severity, latest_repo, latest_repo_findings)
        print(f"Latest-image report written to: {latest_output}")

    if not args.skip_cleanup:
        cleanup_output = args.output.replace(".xlsx", "-ecr-cleanup.xlsx")
        write_ecr_cleanup_report(cleanup_output, ecr_images, ecr_latest, args.region)
        total_old = sum(
            sum(1 for img in imgs if img["digest"] != ecr_latest.get(repo))
            for repo, imgs in ecr_images.items()
        )
        print(f"ECR cleanup report written to: {cleanup_output} ({total_old} old images across {len(ecr_images)} repos)")
```

### Step 5.6: Write end-to-end integration test

- [ ] **Edit** `tests/test_integration.py` — add a test that writes a prior report and verifies history propagates:

```python
def test_latest_report_inherits_first_discovered_from_prior_report(tmp_path, monkeypatch):
    from datetime import datetime, timezone
    from report import (
        normalize_findings, apply_history, load_history,
        build_severity_summary, build_repo_summary, build_repo_findings,
        write_report,
    )

    # Step 1: write a "prior" report with an old date for CVE-A in app-a
    old_date = datetime(2025, 1, 1, tzinfo=timezone.utc)
    prior_findings = [{
        "repo": "app-a",
        "severity": "HIGH",
        "title": "CVE-A",
        "remediation": "",
        "first_observed": old_date,
        "age_days": 400,
        "age_bucket": "> 90 days",
        "vulnerability_id": "CVE-2025-0001",
    }]
    prior_path = str(tmp_path / "111-inspector-report-250101-1200-latest.xlsx")
    write_report(
        prior_path,
        build_severity_summary(prior_findings),
        build_repo_summary(prior_findings),
        build_repo_findings(prior_findings),
    )

    # Step 2: simulate current Inspector findings where the image is brand-new
    new_date = datetime(2026, 4, 1, tzinfo=timezone.utc)
    current = [{
        "repo": "app-a",
        "severity": "HIGH",
        "title": "CVE-A",
        "remediation": "",
        "first_observed": new_date,
        "age_days": 13,
        "age_bucket": "< 30 days",
        "vulnerability_id": "CVE-2025-0001",
    }]

    # Step 3: load history and apply
    history = load_history(str(tmp_path), "111", max_age_days=600,
                           now=datetime(2026, 4, 14, tzinfo=timezone.utc))
    assert history[("app-a", "CVE-A")] == old_date
    matched = apply_history(current, history, now=datetime(2026, 4, 14, tzinfo=timezone.utc))
    assert matched == 1
    assert current[0]["first_observed"] == old_date
    assert current[0]["age_bucket"] == "> 90 days"
```

### Step 5.7: Run full test suite

Run: `python -m pytest tests/ -v`
Expected: ALL PASS.

### Step 5.8: Manual smoke test (recommended, optional)

- [ ] **If AWS credentials are available**, run against a real account:

```bash
python report.py --output smoke-test.xlsx
```

Verify:
- New column `Vulnerability ID` appears in per-repo sheets of both `smoke-test.xlsx` and `smoke-test-latest.xlsx`
- On a second run: output shows `Applied N first-discovered dates from M historical entries.`

### Step 5.9: Commit

```bash
git add report.py tests/test_cli.py tests/test_integration.py
git commit -m "feat: preserve first-discovered dates via historical report lookup"
```

---

## Task 6: Update README

**Files:**
- Modify: `README.md:92-103` (options table)
- Modify: `README.md:127-137` (latest report description)

### Step 6.1: Add the new flag to the options table

- [ ] **Edit** `README.md` — insert a row for `--history-days` in the options table between the `--region` row and `--skip-latest` row:

```markdown
| `--history-days DAYS` | Look back N days of past `-latest.xlsx` reports to preserve first-discovered dates (0 to disable) | `60` |
```

### Step 6.2: Document the history behavior under "Latest-image report"

- [ ] **Edit** `README.md:133-137` — replace the latest-report section with:

```markdown
### 2. Latest-image report (`*-inspector-report-*-latest.xlsx`)

Same structure as the main report, but filtered to only include findings from the latest (most recently pushed) image per repository. If the latest image in ECR has no Inspector findings, that repository is excluded entirely.

**First-discovered preservation:** AWS Inspector resets `firstObservedAt` when a new image digest replaces the previous latest image — even if the underlying CVE is unchanged. To preserve the true first-observed date, this tool scans the output directory for past `-latest.xlsx` reports (by default within the last 60 days, matching the current AWS account). When a finding's `(repository, title)` matches an entry in a past report, the earliest historical date is used instead. Disable with `--history-days 0`. Reports generated with a custom `--output` name that doesn't match the default pattern are not picked up as history.

Skip with `--skip-latest`.
```

### Step 6.3: Verify the README renders sensibly

- [ ] **Open** `README.md` in a Markdown previewer (VS Code, IDE, or GitHub preview) and confirm the table and section look correct. No automated test needed.

### Step 6.4: Commit

```bash
git add README.md
git commit -m "docs: document --history-days flag and history behavior"
```

---

## Self-Review Checklist

Covered before execution:
- [x] **Spec coverage**: Every requirement the user explicitly stated is in a task
  - Vulnerability ID as last column → Task 1
  - Read repo names from Repository Summary → Task 3 (`_repos_in_order_from_summary`)
  - Match by exact title → Task 3 (`(repo, title)` keys)
  - 60-day default window → Task 5 (`--history-days` default 60)
  - Minimize modifications → all logic added to `report.py`, no new production modules
- [x] **Placeholder scan**: No TBDs, no "handle edge cases" hand-waves, every code step shows actual code
- [x] **Type consistency**: All function signatures and property names match across tasks
  - `load_history(search_dir, account_id, max_age_days, now=None)` used identically in Tasks 4 and 5
  - `apply_history(findings, history, now=None)` returns int count, used identically
  - `vulnerability_id` key used consistently in dicts across Tasks 1, 4, 5

## Risks and Mitigations

| Risk | Mitigation |
|---|---|
| Custom `--output` path breaks filename-based history lookup | Document in README; users who rely on history should use the default filename pattern |
| Inspector changes title formatting → matches break | `vulnerability_id` column now written, allowing future version to match on CVE ID instead |
| Corrupt/locked xlsx file in search dir | `read_history_from_report` returns `{}` on any exception; `load_history` prints a warning and continues |
| Two past reports disagree on `(repo, title)` first-discovered date | `load_history` merges via `min()` — earliest always wins |
| Sheet-name collisions when reading (31-char truncation + `_2` suffix) | `_derive_sheet_name_for_repo` reproduces exactly the write-side algorithm; order comes from `Repository Summary` which was written in the same sorted order |
| Filtered past reports (e.g. `--severity CRITICAL` run) lack some findings | Missing keys simply don't match; current findings retain current `firstObservedAt` (natural fallback) |
