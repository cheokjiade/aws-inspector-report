#!/usr/bin/env python3
"""AWS Inspector v2 ECR vulnerability report generator."""

import argparse
import sys
from datetime import datetime, timezone


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


def main():
    pass


if __name__ == "__main__":
    main()
