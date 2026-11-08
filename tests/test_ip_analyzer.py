from argus.ip_analyzer import analyze_ip


def test_public_ip():
    result = analyze_ip("8.8.8.8")

    assert result["valid"] is True
    assert result["version"] == 4
    assert result["global"] is True
    assert result["private"] is False


def test_private_ip():
    result = analyze_ip("192.168.1.10")

    assert result["valid"] is True
    assert result["private"] is True
    assert result["global"] is False


def test_loopback_ip():
    result = analyze_ip("127.0.0.1")

    assert result["valid"] is True
    assert result["loopback"] is True
    assert result["global"] is False


def test_invalid_ip():
    result = analyze_ip("999.999.999.999")

    assert result["valid"] is False
    assert result["error"] == "Invalid IP address"
