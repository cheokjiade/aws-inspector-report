from unittest.mock import MagicMock, patch, call
import pytest
from report import fetch_findings, parse_args


SAMPLE_FINDING = {
    "findingArn": "arn:aws:inspector2:us-east-1:123456789012:finding/abc123",
    "title": "CVE-2023-1234 - libssl",
    "description": "A buffer overflow vulnerability in libssl.",
    "severity": {"label": "HIGH"},
    "firstObservedAt": "2024-01-01T00:00:00Z",
    "status": "ACTIVE",
    "packageVulnerabilityDetails": {
        "cvss": [],
        "referenceUrls": [],
        "vulnerabilityId": "CVE-2023-1234",
    },
    "remediation": {"recommendation": {"text": "Update libssl to version 3.0.9"}},
    "resources": [
        {
            "type": "AWS_ECR_CONTAINER_IMAGE",
            "details": {
                "awsEcrContainerImage": {
                    "repositoryName": "my-app",
                }
            },
        }
    ],
}


@patch("report.boto3.client")
def test_fetch_findings_returns_list(mock_client_factory):
    mock_client = MagicMock()
    mock_client_factory.return_value = mock_client
    paginator = MagicMock()
    mock_client.get_paginator.return_value = paginator
    paginator.paginate.return_value = [{"findings": [SAMPLE_FINDING]}]

    args = parse_args([])
    result = fetch_findings(args)

    assert len(result) == 1
    assert result[0]["findingArn"] == SAMPLE_FINDING["findingArn"]


@patch("report.boto3.client")
def test_fetch_findings_builds_severity_filter(mock_client_factory):
    mock_client = MagicMock()
    mock_client_factory.return_value = mock_client
    paginator = MagicMock()
    mock_client.get_paginator.return_value = paginator
    paginator.paginate.return_value = [{"findings": []}]

    args = parse_args(["--severity", "CRITICAL", "--severity", "HIGH"])
    fetch_findings(args)

    call_kwargs = paginator.paginate.call_args[1]
    severities = call_kwargs["filterCriteria"]["severity"]
    labels = [s["value"] for s in severities]
    assert "CRITICAL" in labels
    assert "HIGH" in labels


@patch("report.boto3.client")
def test_fetch_findings_builds_repo_filter(mock_client_factory):
    mock_client = MagicMock()
    mock_client_factory.return_value = mock_client
    paginator = MagicMock()
    mock_client.get_paginator.return_value = paginator
    paginator.paginate.return_value = [{"findings": []}]

    args = parse_args(["--repo", "my-app"])
    fetch_findings(args)

    call_kwargs = paginator.paginate.call_args[1]
    repos = call_kwargs["filterCriteria"]["ecrImageRepositoryName"]
    assert repos[0]["value"] == "my-app"


@patch("report.boto3.client")
def test_fetch_findings_multi_repo_filters_client_side(mock_client_factory):
    mock_client = MagicMock()
    mock_client_factory.return_value = mock_client
    paginator = MagicMock()
    mock_client.get_paginator.return_value = paginator

    finding_app_a = {
        **SAMPLE_FINDING,
        "findingArn": "arn:1",
        "resources": [{"type": "AWS_ECR_CONTAINER_IMAGE", "details": {"awsEcrContainerImage": {"repositoryName": "app-a"}}}]
    }
    finding_app_b = {
        **SAMPLE_FINDING,
        "findingArn": "arn:2",
        "resources": [{"type": "AWS_ECR_CONTAINER_IMAGE", "details": {"awsEcrContainerImage": {"repositoryName": "app-b"}}}]
    }
    finding_other = {
        **SAMPLE_FINDING,
        "findingArn": "arn:3",
        "resources": [{"type": "AWS_ECR_CONTAINER_IMAGE", "details": {"awsEcrContainerImage": {"repositoryName": "other"}}}]
    }
    paginator.paginate.return_value = [{"findings": [finding_app_a, finding_app_b, finding_other]}]

    args = parse_args(["--repo", "app-a", "--repo", "app-b"])
    result = fetch_findings(args)

    assert len(result) == 2
    arns = {f["findingArn"] for f in result}
    assert "arn:1" in arns
    assert "arn:2" in arns
    assert "arn:3" not in arns

    # Verify no repo filter was sent to the API (client-side filtering used)
    call_kwargs = paginator.paginate.call_args[1]
    assert "ecrImageRepositoryName" not in call_kwargs["filterCriteria"]


@patch("report.boto3.client")
def test_fetch_findings_no_severity_filter_when_empty(mock_client_factory):
    mock_client = MagicMock()
    mock_client_factory.return_value = mock_client
    paginator = MagicMock()
    mock_client.get_paginator.return_value = paginator
    paginator.paginate.return_value = [{"findings": []}]

    args = parse_args([])
    fetch_findings(args)

    call_kwargs = paginator.paginate.call_args[1]
    assert "severity" not in call_kwargs["filterCriteria"]


@patch("report.boto3.client")
def test_fetch_findings_paginates(mock_client_factory):
    mock_client = MagicMock()
    mock_client_factory.return_value = mock_client
    paginator = MagicMock()
    mock_client.get_paginator.return_value = paginator
    page2_finding = dict(SAMPLE_FINDING, findingArn="arn:aws:inspector2:us-east-1:123:finding/def456")
    paginator.paginate.return_value = [
        {"findings": [SAMPLE_FINDING]},
        {"findings": [page2_finding]},
    ]

    args = parse_args([])
    result = fetch_findings(args)

    assert len(result) == 2
