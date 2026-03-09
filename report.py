#!/usr/bin/env python3
"""AWS Inspector v2 ECR vulnerability report generator."""

import argparse
import sys
from datetime import datetime, timezone

import boto3


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNTRIAGED"]
AGE_BUCKETS = ["< 30 days", "30-60 days", "60-90 days", "> 90 days"]


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

    # Pass repo filter only for single repo (API uses AND for multiple values).
    # For multiple repos, filter client-side after fetching.
    if len(args.repo) == 1:
        filter_criteria["ecrImageRepositoryName"] = [
            {"comparison": "EQUALS", "value": args.repo[0]}
        ]

    findings = []
    for page in paginator.paginate(filterCriteria=filter_criteria):
        findings.extend(page.get("findings", []))

    # Client-side repo filter when multiple repos are specified
    if len(args.repo) > 1:
        repo_set = set(args.repo)
        findings = [
            f for f in findings
            if any(
                resource.get("details", {}).get("awsEcrContainerImage", {}).get("repositoryName") in repo_set
                for resource in f.get("resources", [])
            )
        ]

    return findings


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


def main():
    pass


if __name__ == "__main__":
    main()
