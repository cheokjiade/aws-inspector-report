import os
import sys
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone, timedelta
import pytest
import openpyxl
from report import main


def make_raw_finding(severity="HIGH", repo="my-app", days_ago=10):
    first_observed = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return {
        "findingArn": f"arn:aws:inspector2:us-east-1:123:finding/{repo}-{severity}",
        "title": f"CVE-2023-1234 - {repo}",
        "title": f"Vulnerability in {repo}.",
        "severity": {"label": severity},
        "firstObservedAt": first_observed.isoformat(),
        "status": "ACTIVE",
        "remediation": {"recommendation": {"text": f"Fix {repo}"}},
        "resources": [{
            "type": "AWS_ECR_CONTAINER_IMAGE",
            "details": {"awsEcrContainerImage": {"repositoryName": repo}}
        }],
    }


@patch("report.boto3.client")
def test_main_creates_report(mock_client_factory, tmp_path):
    mock_client = MagicMock()
    mock_client_factory.return_value = mock_client
    paginator = MagicMock()
    mock_client.get_paginator.return_value = paginator
    paginator.paginate.return_value = [{
        "findings": [
            make_raw_finding("CRITICAL", "app-a", 5),
            make_raw_finding("HIGH", "app-a", 100),
            make_raw_finding("MEDIUM", "app-b", 45),
        ]
    }]

    output = str(tmp_path / "integration_report.xlsx")
    sys.argv = ["report.py", "--output", output]
    main()

    assert os.path.exists(output)
    wb = openpyxl.load_workbook(output)
    assert "Severity Summary" in wb.sheetnames
    assert "Repository Summary" in wb.sheetnames
    assert "app-a" in wb.sheetnames
    assert "app-b" in wb.sheetnames


@patch("report.boto3.client")
def test_main_empty_findings_creates_report(mock_client_factory, tmp_path):
    mock_client = MagicMock()
    mock_client_factory.return_value = mock_client
    paginator = MagicMock()
    mock_client.get_paginator.return_value = paginator
    paginator.paginate.return_value = [{"findings": []}]

    output = str(tmp_path / "empty_report.xlsx")
    sys.argv = ["report.py", "--output", output]
    main()

    assert os.path.exists(output)
    wb = openpyxl.load_workbook(output)
    assert "Severity Summary" in wb.sheetnames
