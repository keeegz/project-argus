
import ipaddress


def analyze_ip(ip_address: str) -> dict:
    """Validate and classify an IPv4 or IPv6 address."""

    try:
        ip = ipaddress.ip_address(ip_address)

    except ValueError:
        return {
            "ip": ip_address,
            "valid": False,
            "error": "Invalid IP address"
        }

    return {
        "ip": str(ip),
        "valid": True,
        "version": ip.version,
        "private": ip.is_private,
        "global": ip.is_global,
        "loopback": ip.is_loopback,
        "multicast": ip.is_multicast,
        "reserved": ip.is_reserved
    }
