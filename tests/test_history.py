import os
from datetime import datetime, timezone, timedelta
import pytest
from report import parse_report_filename, find_history_reports
from report import (
    read_history_from_report,
    load_history,
    apply_history,
    age_bucket,
    write_report,
    build_severity_summary,
    build_repo_summary,
    build_repo_findings,
)


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


def test_parse_report_filename_invalid_date_in_valid_pattern():
    # Regex matches (6 digits + 4 digits) but date is semantically invalid
    assert parse_report_filename("111-inspector-report-261399-2500-latest.xlsx") is None


def test_find_history_reports_includes_report_at_exact_cutoff(tmp_path):
    # Report timestamped exactly at (now - max_age_days) should be included (cutoff is strict <)
    exact_cutoff = NOW - timedelta(days=60)
    fname = f"111-inspector-report-{exact_cutoff.strftime('%y%m%d-%H%M')}-latest.xlsx"
    (tmp_path / fname).write_bytes(b"")
    result = find_history_reports(str(tmp_path), "111", max_age_days=60, now=NOW)
    assert len(result) == 1
    assert result[0].endswith(fname)


def test_find_history_reports_excludes_report_just_before_cutoff(tmp_path):
    # One minute older than the cutoff — must be excluded
    just_before = NOW - timedelta(days=60, minutes=1)
    fname = f"111-inspector-report-{just_before.strftime('%y%m%d-%H%M')}-latest.xlsx"
    (tmp_path / fname).write_bytes(b"")
    result = find_history_reports(str(tmp_path), "111", max_age_days=60, now=NOW)
    assert result == []


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
    # Two repos that both truncate to the same 31-char prefix
    repo_long_a = "a" * 32 + "X"
    repo_long_b = "a" * 32 + "Y"
    date_a = datetime(2025, 10, 1, tzinfo=timezone.utc)
    date_b = datetime(2025, 11, 1, tzinfo=timezone.utc)
    findings = [
        _finding(repo_long_a, "Title A", date_a),
        _finding(repo_long_b, "Title B", date_b),
    ]
    path = str(tmp_path / "111-inspector-report-251001-1000-latest.xlsx")
    _write_fixture_report(path, findings)

    history = read_history_from_report(path)
    # Distinct dates confirm each repo's sheet was resolved correctly,
    # not just that both keys landed in the result.
    assert history[(repo_long_a, "Title A")] == date_a
    assert history[(repo_long_b, "Title B")] == date_b


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
