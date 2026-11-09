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