from datetime import datetime, timezone
from argus.ip_analyzer import analyze_ip


def main():
    print("=" * 50)
    print("PROJECT ARGUS")
    print("Threat Intelligence & Security Analysis Engine")
    print("=" * 50)

    timestamp = datetime.now(timezone.utc)

    print("[+] Engine Status: ONLINE")
    print(f"[+] Initialization Time: {timestamp:%Y-%m-%d %H:%M:%S} UTC")
    print("[+] IP Analysis Module: LOADED")
    print("=" * 50)

    ip_address = input("\nEnter an IP address to analyze: ")

    result = analyze_ip(ip_address.strip())

    print("\n--- ARGUS IP ANALYSIS REPORT ---")

    for key, value in result.items():
        print(f"{key.upper()}: {value}")

    print("\n[+] Analysis Complete")


if __name__ == "__main__":
    main()
