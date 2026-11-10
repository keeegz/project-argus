import httpx


VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"


def lookup_ip(ip_address: str, api_key: str) -> dict:
    """
    Retrieve VirusTotal intelligence for an IP address.
    """

    url = f"{VIRUSTOTAL_BASE_URL}/ip_addresses/{ip_address}"

    headers = {
        "x-apikey": api_key
    }

    response = httpx.get(
        url,
        headers=headers,
        timeout=10.0
    )

    response.raise_for_status()

    return response.json()


def summarize_ip_report(report: dict) -> dict:
    """
    Convert a VirusTotal IP report into a structured
    intelligence summary.
    """
    data = report["data"]
    attributes = data["attributes"]

    stats = attributes.get("last_analysis_stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    if malicious > 0 or suspicious > 0:
        assessment = "Review required"
    else:
        assessment = "No detections reported"

    return {
        "indicator": data["id"],
        "source": "VirusTotal",
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attributes.get("reputation"),
        "assessment": assessment,
    }