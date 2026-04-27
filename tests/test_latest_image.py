from datetime import datetime, timezone
from unittest.mock import patch, MagicMock
from report import (
    filter_latest_image_findings,
    fetch_ecr_images,
    fetch_all_ecr_repos,
    latest_digests_from_images,
)


def _make_finding(repo, image_hash, pushed_at, severity="HIGH"):
    """Create a minimal raw Inspector finding with ECR image details."""
    return {
        "severity": severity,
        "title": f"Vuln in {repo}",
        "firstObservedAt": datetime(2024, 6, 1, tzinfo=timezone.utc),
        "resources": [{
            "details": {
                "awsEcrContainerImage": {
                    "repositoryName": repo,
                    "imageHash": image_hash,
                    "pushedAt": pushed_at,
                }
            }
        }],
    }


def test_selects_latest_image_per_repo():
    old = datetime(2024, 1, 1, tzinfo=timezone.utc)
    new = datetime(2024, 6, 1, tzinfo=timezone.utc)

    findings = [
        _make_finding("app-a", "sha256:old111", old),
        _make_finding("app-a", "sha256:new222", new),
        _make_finding("app-b", "sha256:only33", old),
    ]
    result = filter_latest_image_findings(findings)

    repos_and_hashes = [
        (_get_repo(f), _get_hash(f)) for f in result
    ]
    assert ("app-a", "sha256:new222") in repos_and_hashes
    assert ("app-a", "sha256:old111") not in repos_and_hashes
    assert ("app-b", "sha256:only33") in repos_and_hashes


def test_multiple_findings_same_latest_image():
    pushed = datetime(2024, 6, 1, tzinfo=timezone.utc)
    findings = [
        _make_finding("app-a", "sha256:aaa", pushed, "HIGH"),
        _make_finding("app-a", "sha256:aaa", pushed, "CRITICAL"),
    ]
    result = filter_latest_image_findings(findings)
    assert len(result) == 2


def test_skips_findings_without_image_details():
    finding_no_details = {
        "severity": "HIGH",
        "title": "No image",
        "firstObservedAt": datetime(2024, 6, 1, tzinfo=timezone.utc),
        "resources": [{"details": {}}],
    }
    findings = [
        finding_no_details,
        _make_finding("app-a", "sha256:aaa", datetime(2024, 6, 1, tzinfo=timezone.utc)),
    ]
    result = filter_latest_image_findings(findings)
    assert len(result) == 1


def test_handles_pushed_at_as_string():
    findings = [
        _make_finding("app-a", "sha256:old", "2024-01-01T00:00:00Z"),
        _make_finding("app-a", "sha256:new", "2024-06-01T00:00:00Z"),
    ]
    result = filter_latest_image_findings(findings)
    assert len(result) == 1
    assert _get_hash(result[0]) == "sha256:new"


def test_excludes_repo_when_inspector_latest_differs_from_ecr():
    """If ECR's latest image differs from Inspector's latest, exclude that repo."""
    pushed = datetime(2024, 6, 1, tzinfo=timezone.utc)
    findings = [
        _make_finding("app-a", "sha256:inspector_latest", pushed),
        _make_finding("app-b", "sha256:matches_ecr", pushed),
    ]
    ecr_latest = {
        "app-a": "sha256:ecr_newest_image",   # different → exclude app-a
        "app-b": "sha256:matches_ecr",         # same → keep app-b
    }
    result = filter_latest_image_findings(findings, ecr_latest)
    repos = [_get_repo(f) for f in result]
    assert "app-a" not in repos
    assert "app-b" in repos
    assert len(result) == 1


def test_keeps_repo_when_ecr_latest_not_available():
    """If ECR lookup didn't return a digest for a repo, keep its findings."""
    pushed = datetime(2024, 6, 1, tzinfo=timezone.utc)
    findings = [
        _make_finding("app-a", "sha256:aaa", pushed),
    ]
    ecr_latest = {}  # no ECR info for app-a
    result = filter_latest_image_findings(findings, ecr_latest)
    assert len(result) == 1


def test_ecr_latest_none_behaves_as_before():
    """When ecr_latest is None (not provided), all latest-per-repo findings are kept."""
    old = datetime(2024, 1, 1, tzinfo=timezone.utc)
    new = datetime(2024, 6, 1, tzinfo=timezone.utc)
    findings = [
        _make_finding("app-a", "sha256:old111", old),
        _make_finding("app-a", "sha256:new222", new),
    ]
    result = filter_latest_image_findings(findings, ecr_latest=None)
    assert len(result) == 1
    assert _get_hash(result[0]) == "sha256:new222"


@patch("report.boto3")
def test_fetch_ecr_images(mock_boto3):
    mock_ecr = MagicMock()
    mock_boto3.client.return_value = mock_ecr

    mock_paginator = MagicMock()
    mock_ecr.get_paginator.return_value = mock_paginator
    mock_paginator.paginate.return_value = [
        {
            "imageDetails": [
                {
                    "imageDigest": "sha256:older",
                    "imagePushedAt": datetime(2024, 1, 1, tzinfo=timezone.utc),
                    "imageTags": ["v1.0"],
                    "lastRecordedPullTime": datetime(2024, 2, 1, tzinfo=timezone.utc),
                },
                {
                    "imageDigest": "sha256:newest",
                    "imagePushedAt": datetime(2024, 6, 1, tzinfo=timezone.utc),
                    "imageTags": ["v2.0", "latest"],
                },
            ]
        }
    ]

    result = fetch_ecr_images(["my-repo"], region="us-east-1")
    assert "my-repo" in result
    assert len(result["my-repo"]) == 2
    assert result["my-repo"][0]["digest"] == "sha256:older"
    assert result["my-repo"][0]["tags"] == ["v1.0"]
    assert result["my-repo"][0]["last_pulled"] == datetime(2024, 2, 1, tzinfo=timezone.utc)
    assert result["my-repo"][1]["digest"] == "sha256:newest"
    assert result["my-repo"][1]["tags"] == ["v2.0", "latest"]
    assert result["my-repo"][1]["last_pulled"] is None
    mock_boto3.client.assert_called_once_with("ecr", region_name="us-east-1")


@patch("report.boto3")
def test_fetch_all_ecr_repos(mock_boto3):
    mock_ecr = MagicMock()
    mock_boto3.client.return_value = mock_ecr
    mock_paginator = MagicMock()
    mock_ecr.get_paginator.return_value = mock_paginator
    mock_paginator.paginate.return_value = [
        {"repositories": [{"repositoryName": "app-a"}, {"repositoryName": "app-b"}]},
        {"repositories": [{"repositoryName": "app-c"}]},
    ]
    result = fetch_all_ecr_repos(region="us-east-1")
    assert result == {"app-a", "app-b", "app-c"}
    mock_boto3.client.assert_called_once_with("ecr", region_name="us-east-1")


@patch("report.boto3")
def test_fetch_all_ecr_repos_handles_error(mock_boto3):
    mock_ecr = MagicMock()
    mock_boto3.client.return_value = mock_ecr
    mock_paginator = MagicMock()
    mock_ecr.get_paginator.return_value = mock_paginator
    mock_paginator.paginate.side_effect = Exception("AccessDenied")
    assert fetch_all_ecr_repos() == set()


@patch("report.boto3")
def test_fetch_ecr_images_handles_error(mock_boto3):
    mock_ecr = MagicMock()
    mock_boto3.client.return_value = mock_ecr

    mock_paginator = MagicMock()
    mock_ecr.get_paginator.return_value = mock_paginator
    mock_paginator.paginate.side_effect = Exception("repo not found")

    result = fetch_ecr_images(["missing-repo"])
    assert result == {}


def test_latest_digests_from_images():
    all_images = {
        "app-a": [
            {"digest": "sha256:old", "tags": ["v1"], "pushed_at": datetime(2024, 1, 1, tzinfo=timezone.utc), "last_pulled": None},
            {"digest": "sha256:new", "tags": ["v2"], "pushed_at": datetime(2024, 6, 1, tzinfo=timezone.utc), "last_pulled": None},
        ],
        "app-b": [
            {"digest": "sha256:only", "tags": [], "pushed_at": datetime(2024, 3, 1, tzinfo=timezone.utc), "last_pulled": None},
        ],
    }
    result = latest_digests_from_images(all_images)
    assert result == {"app-a": "sha256:new", "app-b": "sha256:only"}


def test_latest_digests_from_images_empty():
    assert latest_digests_from_images({}) == {}
    assert latest_digests_from_images({"app-a": []}) == {}


def _get_repo(finding):
    return finding["resources"][0]["details"]["awsEcrContainerImage"]["repositoryName"]


def _get_hash(finding):
    return finding["resources"][0]["details"]["awsEcrContainerImage"]["imageHash"]
