from datetime import datetime, timezone
from report import filter_latest_image_findings


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


def _get_repo(finding):
    return finding["resources"][0]["details"]["awsEcrContainerImage"]["repositoryName"]


def _get_hash(finding):
    return finding["resources"][0]["details"]["awsEcrContainerImage"]["imageHash"]
