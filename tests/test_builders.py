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
