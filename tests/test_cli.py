import pytest
from report import parse_args


def test_defaults():
    args = parse_args([])
    assert args.output is None
    assert args.status == ["ACTIVE"]
    assert args.severity == []
    assert args.repo == []
    assert args.region is None


def test_output_flag():
    args = parse_args(["--output", "my_report.xlsx"])
    assert args.output == "my_report.xlsx"


def test_multiple_severities():
    args = parse_args(["--severity", "CRITICAL", "--severity", "HIGH"])
    assert args.severity == ["CRITICAL", "HIGH"]


def test_multiple_repos():
    args = parse_args(["--repo", "app-a", "--repo", "app-b"])
    assert args.repo == ["app-a", "app-b"]


def test_status_override():
    args = parse_args(["--status", "SUPPRESSED"])
    assert args.status == ["SUPPRESSED"]


def test_region_flag():
    args = parse_args(["--region", "ap-southeast-1"])
    assert args.region == "ap-southeast-1"
