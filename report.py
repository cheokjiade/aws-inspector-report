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


def main():
    pass


if __name__ == "__main__":
    main()
