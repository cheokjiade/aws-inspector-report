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
