# AWS Inspector Report — Design Document

**Date:** 2026-03-09

## Overview

A single Python script (`report.py`) that fetches ECR vulnerability findings from AWS Inspector v2 via boto3 and writes a multi-sheet Excel report (`.xlsx`).

## Architecture

**Single file:** `report.py`
**Dependencies:** `boto3`, `openpyxl`

### Data Flow

1. Parse CLI arguments (filters: `--severity`, `--repo`, `--status`, `--output`, `--region`)
2. Create a `boto3` `inspector2` client using environment variable credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION`)
3. Paginate through `list_findings` with a filter expression built from CLI args — ECR package findings only
4. For each finding, extract: repository name, severity, first observed date, description, remediation text
5. Compute age in days from first observed → bucket into `<30 / 30–60 / 60–90 / >90 days`
6. Build three data structures in memory, write to a single `.xlsx` via `openpyxl`

## Excel Output Structure

### Sheet 1 — Severity Summary

| Severity Level | Total | < 30 days | 30–60 days | 60–90 days | > 90 days |
|---|---|---|---|---|---|
| Critical | | | | | |
| High | | | | | |
| Medium | | | | | |
| Low | | | | | |
| Untriaged | | | | | |
| **Total** | | | | | |

### Sheet 2 — Repository Summary

| Amazon ECR Container | Critical | High | Medium | Low | Untriaged | Total |
|---|---|---|---|---|---|---|
| repo-name | | | | | | |
| **Total** | | | | | | |

### Sheet 3+ — Per-Repository Findings (one sheet per repo)

Sheet named after the repository (truncated to 31 chars for Excel limit).
Sorted by severity (Critical → High → Medium → Low → Untriaged), then by First Discovered (oldest first).

| S/N | Description | Remediation | Severity | First Discovered |
|---|---|---|---|---|

**Untriaged** = findings where Inspector severity is `INFORMATIONAL` or absent.

## CLI Interface

```bash
python report.py [OPTIONS]

Options:
  --output FILE        Output filename (default: inspector_report.xlsx)
  --severity LEVEL     Filter by severity: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
                       (repeatable)
  --repo NAME          Filter to specific ECR repo name (repeatable)
  --status STATUS      Filter by finding status (default: ACTIVE)
                       Options: ACTIVE, SUPPRESSED, CLOSED
  --region REGION      AWS region (default: from AWS_DEFAULT_REGION env var)
```

### Examples

```bash
# All active findings
python report.py

# Only Critical and High
python report.py --severity CRITICAL --severity HIGH --output critical_report.xlsx

# Specific repos
python report.py --repo my-app --repo another-service
```

## Credentials

Credentials are provided via environment variables before running:

```bash
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1
python report.py
```
