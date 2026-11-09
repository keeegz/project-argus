import httpx
import pytest

from argus.intelligence.virustotal import lookup_ip


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
    import pytest


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