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

def lookup_file_hash(file_hash: str, api_key: str) -> dict:
    """
    Retrieve VirusTotal intelligence for a file hash.
    """

    url = f"{VIRUSTOTAL_BASE_URL}/files/{file_hash}"

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

def summarize_file_report(report: dict) -> dict:
    """
    Convert a VirusTotal file report into a
    structured threat intelligence summary.
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
        "file_name": attributes.get("meaningful_name"),
        "file_type": attributes.get("type_description"),
        "file_size": attributes.get("size"),
        "sha256": attributes.get("sha256"),
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attributes.get("reputation"),
        "assessment": assessment,
    }

