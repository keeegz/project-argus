import httpx
import pytest

from argus.intelligence.virustotal import (
    lookup_ip,
    summarize_ip_report,
    lookup_file_hash,
    summarize_file_report,
)

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

def test_virustotal_file_hash_success(monkeypatch):
    file_hash = "a" * 64

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {
                "data": {
                    "id": file_hash,
                    "type": "file"
                }
            }

    def fake_get(url, headers, timeout):
        assert url == (
            f"https://www.virustotal.com/api/v3/files/{file_hash}"
        )
        assert headers["x-apikey"] == "test-api-key"
        assert timeout == 10.0

        return FakeResponse()

    monkeypatch.setattr(
        "argus.intelligence.virustotal.httpx.get",
        fake_get
    )

    result = lookup_file_hash(file_hash, "test-api-key")

    assert result["data"]["id"] == file_hash
    assert result["data"]["type"] == "file"

def test_summarize_file_report_with_detections():
    fake_report = {
        "data": {
            "id": "a" * 64,
            "attributes": {
                "meaningful_name": "suspicious.exe",
                "type_description": "Win32 EXE",
                "size": 245760,
                "sha256": "a" * 64,
                "reputation": -10,
                "last_analysis_stats": {
                    "malicious": 42,
                    "suspicious": 3,
                    "harmless": 28,
                    "undetected": 5,
                },
            },
        },
    }

    summary = summarize_file_report(fake_report)

    assert summary["file_name"] == "suspicious.exe"
    assert summary["file_type"] == "Win32 EXE"
    assert summary["malicious"] == 42
    assert summary["suspicious"] == 3
    assert summary["assessment"] == "Review required"


def test_summarize_file_report_without_detections():
    fake_report = {
        "data": {
            "id": "b" * 64,
            "attributes": {
                "meaningful_name": "unknown.exe",
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 60,
                    "undetected": 10,
                },
            },
        },
    }

    summary = summarize_file_report(fake_report)

    assert summary["malicious"] == 0
    assert summary["suspicious"] == 0
    assert summary["harmless"] == 60
    assert summary["assessment"] == "No detections reported"
