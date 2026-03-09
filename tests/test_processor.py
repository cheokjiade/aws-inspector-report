from datetime import datetime, timezone, timedelta
import pytest
from report import normalize_findings, age_bucket


def make_finding(severity="HIGH", repo="my-app", days_ago=10, remediation_text=None):
    first_observed = datetime.now(timezone.utc) - timedelta(days=days_ago)
    finding = {
        "title": "CVE-2023-1234 - libssl",
        "description": "A buffer overflow in libssl.",
        "severity": {"label": severity},
        "firstObservedAt": first_observed.isoformat(),
        "remediation": {},
        "resources": [{
            "type": "AWS_ECR_CONTAINER_IMAGE",
            "details": {
                "awsEcrContainerImage": {"repositoryName": repo}
            }
        }],
    }
    if remediation_text:
        finding["remediation"] = {"recommendation": {"text": remediation_text}}
    return finding


# --- age_bucket tests ---

def test_age_bucket_under_30():
    assert age_bucket(29) == "< 30 days"

def test_age_bucket_30_to_60():
    assert age_bucket(30) == "30-60 days"
    assert age_bucket(60) == "30-60 days"

def test_age_bucket_60_to_90():
    assert age_bucket(61) == "60-90 days"
    assert age_bucket(90) == "60-90 days"

def test_age_bucket_over_90():
    assert age_bucket(91) == "> 90 days"


# --- normalize_findings tests ---

def test_normalize_basic_fields():
    raw = [make_finding(severity="HIGH", repo="my-app", days_ago=10)]
    result = normalize_findings(raw)
    assert len(result) == 1
    f = result[0]
    assert f["repo"] == "my-app"
    assert f["severity"] == "HIGH"
    assert f["age_bucket"] == "< 30 days"
    assert f["description"] == "A buffer overflow in libssl."


def test_normalize_severity_as_plain_string():
    """Real AWS API sometimes returns severity as a plain string, not a dict."""
    raw = [make_finding(severity="HIGH")]
    raw[0]["severity"] = "HIGH"  # plain string instead of {"label": "HIGH"}
    result = normalize_findings(raw)
    assert result[0]["severity"] == "HIGH"


def test_normalize_first_observed_as_datetime_object():
    """boto3 deserializes firstObservedAt as a datetime object, not a string."""
    raw = [make_finding(days_ago=10)]
    raw[0]["firstObservedAt"] = datetime.now(timezone.utc) - timedelta(days=10)
    result = normalize_findings(raw)
    assert result[0]["age_bucket"] == "< 30 days"


def test_normalize_informational_becomes_untriaged():
    raw = [make_finding(severity="INFORMATIONAL")]
    result = normalize_findings(raw)
    assert result[0]["severity"] == "UNTRIAGED"


def test_normalize_missing_severity_becomes_untriaged():
    raw = [make_finding()]
    raw[0]["severity"] = {}
    result = normalize_findings(raw)
    assert result[0]["severity"] == "UNTRIAGED"


def test_normalize_remediation_text():
    raw = [make_finding(remediation_text="Update libssl to 3.0.9")]
    result = normalize_findings(raw)
    assert result[0]["remediation"] == "Update libssl to 3.0.9"


def test_normalize_empty_remediation():
    raw = [make_finding()]
    result = normalize_findings(raw)
    assert result[0]["remediation"] == ""


def test_normalize_age_over_90():
    raw = [make_finding(days_ago=100)]
    result = normalize_findings(raw)
    assert result[0]["age_bucket"] == "> 90 days"


def test_normalize_missing_repo_becomes_unknown():
    raw = [{
        "title": "CVE-2023-1234",
        "description": "A vulnerability.",
        "severity": {"label": "HIGH"},
        "firstObservedAt": (datetime.now(timezone.utc) - timedelta(days=5)).isoformat(),
        "remediation": {},
        "resources": [],
    }]
    result = normalize_findings(raw)
    assert result[0]["repo"] == "(unknown)"
