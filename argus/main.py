import os
import httpx

from argus.intelligence.virustotal import (
    lookup_file_hash,
    summarize_file_report,
)

from datetime import datetime, timezone

from argus.ip_analyzer import analyze_ip
from argus.hash_analyzer import identify_hash_type


def main():
    print("=" * 50)
    print("PROJECT ARGUS")
    print("Threat Intelligence & Security Analysis Engine")
    print("=" * 50)

    timestamp = datetime.now(timezone.utc)

    print("[+] Engine Status: ONLINE")
    print(f"[+] Initialization Time: {timestamp:%Y-%m-%d %H:%M:%S} UTC")
    print("[+] IP Analysis Module: LOADED")
    print("[+] Hash Analysis Module: LOADED")
    print("=" * 50)

    
    while True:
        print("\n" + "=" * 50)
        print("ARGUS MAIN MENU")
        print("=" * 50)

        print("1. IP Address")
        print("2. File Hash")
        print("3. Exit")

        selection = input("\nSelection: ").strip()

        if selection == "1":
            ip_address = input("\nEnter an IP address: ")

            result = analyze_ip(ip_address.strip())

            print("\n--- ARGUS IP ANALYSIS REPORT ---")

            for key, value in result.items():
                print(f"{key.upper()}: {value}")

        elif selection == "2":
            file_hash = input("\nEnter a file hash: ").strip()

            hash_type = identify_hash_type(file_hash)

            print("\n--- ARGUS FILE HASH REPORT ---")
            print(f"HASH: {file_hash}")
            print(f"HASH TYPE: {hash_type}")

            if hash_type == "Invalid":
                print("[-] Invalid or unsupported file hash.")
            else:
                print("[+] Hash format validated successfully.")

                api_key = os.getenv("VT_API_KEY")

                if not api_key:
                    print("[-] VirusTotal API key not configured.")
                else:
                    print("\n[+] Querying VirusTotal...")

                    try:
                        report = lookup_file_hash(file_hash, api_key)
                        summary = summarize_file_report(report)

                        print("\n--- VIRUSTOTAL INTELLIGENCE ---")

                        for key, value in summary.items():
                            print(f"{key.upper()}: {value}")

                    except httpx.HTTPStatusError as error:
                        status = error.response.status_code

                        if status == 404:
                            print("[-] Hash not found in VirusTotal.")
                        elif status == 429:
                            print("[-] VirusTotal API rate limit exceeded.")
                        else:
                            print(f"[-] VirusTotal HTTP error: {status}")

                    except httpx.RequestError as error:
                        print(f"[-] VirusTotal connection error: {error}")

        elif selection == "3":
            print("\n[+] Shutting down Project ARGUS.")
            break

        else:
            print("\n[-] Invalid selection. Please try again.")

        print("\n[+] Investigation Complete")
        input("\nPress Enter to return to the main menu...")

if __name__ == "__main__":
    main()
