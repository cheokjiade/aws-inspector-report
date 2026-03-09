# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

**aws-inspector-report** — a project for generating reports from AWS Inspector findings. No source code has been committed yet; this file should be updated once the project structure is established.

## IntelliJ IDEA Configuration

The `.idea/` directory contains IDE project settings with:
- AWS plugin configured for region `us-east-1`, profile `default`
- Language support configured for TypeScript/JavaScript, Kotlin, and Vue

## Initial Instructions
A project, preferably python or bash to capture information from AWS Inspector and output reports
1. A summary table of the vulnerability findings by severity level and age of findings
The columns are
Severity Level: Critical/High/Medium/Low/Untriaged
Total Number of Vulnerabilities: Total for each severity
Age of the findings, broken up into the following periods: < 30 days / 30 - 60 days / 60 - 90 days / > 90 days

2. A summary table of the severity level of findings for each container repository
The columns are
Amazon ECR Container: Listing each container repository as its own row
Columns for Critical/High/Medium/Low/Untriaged severity level. For the total number of each finding per repository, and an overall total.

3. A Finding table for each repository
The columns are
S/N: sequential number
Description: description of the finding
Remediation: remediation step provided by AWS Inspector if any
Severity:
First Discovered:
