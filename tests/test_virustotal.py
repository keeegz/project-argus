import httpx
import pytest

from argus.intelligence.virustotal import lookup_ip, summarize_ip_report

def test_virustotal_success(monkeypatch):
    fake_data = {
        "data": {
            "id": "8.8.8.8",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 85,
                }
            },
        }
    }

    def fake_get(url, headers, timeout):
        assert url.endswith("/ip_addresses/8.8.8.8")
        assert headers["x-apikey"] == "test-api-key"
        assert timeout == 10.0

        request = httpx.Request("GET", url)
        return httpx.Response(
            200,
            json=fake_data,
            request=request,
        )

    monkeypatch.setattr(httpx, "get", fake_get)

    result = lookup_ip("8.8.8.8", "test-api-key")

    assert result == fake_data
    assert result["data"]["attributes"]["last_analysis_stats"]["malicious"] == 0


def test_virustotal_rate_limit(monkeypatch):

    def fake_get(url, headers, timeout):
        request = httpx.Request("GET", url)

        return httpx.Response(
            429,
            json={"error": "Rate limit exceeded"},
            request=request,
        )

    monkeypatch.setattr(httpx, "get", fake_get)

    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        lookup_ip("8.8.8.8", "test-api-key")

    assert exc_info.value.response.status_code == 429

def test_summarize_ip_report_with_detection():
    report = {
        "data": {
            "id": "8.8.8.8",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 1,
                    "suspicious": 0,
                    "harmless": 53,
                    "undetected": 38,
                },
                "reputation": 100,
            },
        },
    }

    summary = summarize_ip_report(report)

    assert summary["indicator"] == "8.8.8.8"
    assert summary["source"] == "VirusTotal"
    assert summary["malicious"] == 1
    assert summary["suspicious"] == 0
    assert summary["harmless"] == 53
    assert summary["undetected"] == 38
    assert summary["reputation"] == 100
    assert summary["assessment"] == "Review required"

def test_summarize_ip_report_without_detections():
    report = {
        "data": {
            "id": "1.1.1.1",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 80,
                    "undetected": 10,
                },
                "reputation": 50,
            },
        },
    }

    summary = summarize_ip_report(report)

    assert summary["indicator"] == "1.1.1.1"
    assert summary["malicious"] == 0
    assert summary["suspicious"] == 0
    assert summary["assessment"] == "No detections reported"