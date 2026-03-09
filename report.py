#!/usr/bin/env python3
"""AWS Inspector v2 ECR vulnerability report generator."""

import argparse
import sys
from datetime import datetime, timezone

import boto3
import openpyxl
from openpyxl.styles import Font


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
        severity_raw = f.get("severity", {})
        if isinstance(severity_raw, dict):
            severity_label = severity_raw.get("label", "")
        else:
            severity_label = str(severity_raw) if severity_raw else ""
        if severity_label not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            severity_label = "UNTRIAGED"

        first_observed_raw = f.get("firstObservedAt", "")
        try:
            if isinstance(first_observed_raw, datetime):
                first_observed = first_observed_raw
                if first_observed.tzinfo is None:
                    first_observed = first_observed.replace(tzinfo=timezone.utc)
            else:
                first_observed = datetime.fromisoformat(
                    str(first_observed_raw).replace("Z", "+00:00")
                )
        except (ValueError, AttributeError):
            first_observed = now

        days_old = (now - first_observed).days
        vulnerable_packages = f.get("packageVulnerabilityDetails", {}).get("vulnerablePackages", [])
        has_fixed_version = any(pkg.get("fixedInVersion") for pkg in vulnerable_packages)
        remediation_parts = []
        if has_fixed_version:
            remediation_parts.append(
                "Upgrade your installed software packages to the proposed fixed in version and release."
            )
            for pkg in vulnerable_packages:
                pkg_fix = (pkg.get("remediation", "") or "").strip()
                if pkg_fix and pkg_fix not in remediation_parts:
                    remediation_parts.append(pkg_fix)
        else:
            rec_text = (f.get("remediation", {}).get("recommendation", {}).get("text", "") or "").strip()
            if rec_text and rec_text.lower() != "none provided":
                remediation_parts.append(rec_text)
        remediation = "\n".join(remediation_parts)

        repo = ""
        for resource in f.get("resources", []):
            details = resource.get("details", {}).get("awsEcrContainerImage", {})
            if details.get("repositoryName"):
                repo = details["repositoryName"]
                break
        if not repo:
            repo = "(unknown)"

        results.append({
            "repo": repo,
            "severity": severity_label,
            "title": f.get("title", ""),
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
            key=lambda item: (severity_rank.get(item["severity"], 99), item["first_observed"])
        )
    return grouped


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
    used_sheet_names = set()
    for repo in sorted(repo_findings.keys()):
        base = repo[:31]
        sheet_name = base
        counter = 2
        while sheet_name in used_sheet_names:
            suffix = f"_{counter}"
            sheet_name = base[:31 - len(suffix)] + suffix
            counter += 1
        used_sheet_names.add(sheet_name)
        ws = wb.create_sheet(sheet_name)
        ws.append(["S/N", "Title", "Remediation", "Severity", "First Discovered"])
        for col in range(1, 6):
            _bold(ws, 1, col)
        for i, f in enumerate(repo_findings[repo], start=1):
            ws.append([
                i,
                f["title"],
                f["remediation"],
                f["severity"].capitalize(),
                f["first_observed"].strftime("%Y-%m-%d"),
            ])
        ws.freeze_panes = "A2"

    wb.save(output_path)


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


if __name__ == "__main__":
    main()
