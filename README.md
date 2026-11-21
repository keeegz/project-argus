# Project ARGUS

**Automated Reputation Gathering & Unified Security**

A local-first, Python-based threat intelligence enrichment and security analysis tool designed to support Security Operations Center (SOC) investigations.

## Overview

Project ARGUS is an independently developed cybersecurity engineering project focused on automating indicator analysis, threat intelligence enrichment, and security investigation workflows.

ARGUS enables analysts to validate indicators, retrieve intelligence from external providers, and generate structured, explainable investigation results.

The project emphasizes modular Python development, secure API integration, automated testing, and practical SOC workflows.

## Current Capabilities

### IP Address Analysis
- Supports IPv4 and IPv6 addresses.
- Identifies private, global, loopback, multicast, and reserved addresses.
- Validates input and handles malformed IP addresses.
- Generates structured IP classification reports.

### File Hash Analysis
- Identifies MD5, SHA-1, and SHA-256 hash formats.
- Validates hexadecimal characters and expected hash lengths.
- Rejects invalid or unsupported hash formats.
- Supports VirusTotal file hash enrichment.

### VirusTotal Threat Intelligence
- Integrates with VirusTotal API v3.
- Supports IP and file report retrieval through reusable Python functions.
- Retrieves file metadata, detection statistics, and reputation information.
- Generates structured intelligence summaries.
- Handles HTTP errors, including missing reports and API rate limits.
- Uses environment variables to access API credentials in the CLI.

**Integration status:** Live VirusTotal file hash lookups have been successfully validated. IP reputation retrieval is implemented and unit-tested but is not yet exposed through the CLI.

### Interactive Investigation Console
- Menu-driven command-line interface.
- Supports repeated investigations within a single session.
- Allows analysts to investigate IP addresses or file hashes.
- Displays structured analysis results.
- Provides a controlled exit option.

## Architecture

```text
project-argus/
├── argus/
│   ├── __init__.py
│   ├── main.py
│   ├── ip_analyzer.py
│   ├── hash_analyzer.py
│   └── intelligence/
│       ├── __init__.py
│       └── virustotal.py
├── tests/
│   ├── test_ip_analyzer.py
│   ├── test_hash_analyzer.py
│   └── test_virustotal.py
├── .gitignore
├── README.md
└── requirements.txt
```

### Investigation Workflow

1. Analyst selects an indicator type.
2. ARGUS validates and classifies the indicator.
3. For valid file hashes, ARGUS queries VirusTotal when an API key is configured.
4. The application parses available threat intelligence.
5. ARGUS displays a structured investigation report.
6. The analyst can return to the main menu for another investigation.

## Getting Started

### Prerequisites

- Python 3.13
- Git
- VirusTotal API key for live file intelligence lookups

### Installation

Clone the repository:

```powershell
git clone https://github.com/keeegz/project-argus.git
cd project-argus
```

Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

### Configure VirusTotal

In PowerShell, enter:

```powershell
$env:VT_API_KEY = Read-Host "Enter VirusTotal API key"
```

The environment variable is available to applications launched from that PowerShell session. Do not store API keys in source code or commit them to GitHub.

### Launch ARGUS

```powershell
python -m argus.main
```

Select an investigation type from the interactive menu.

## Example Investigation

The following results were observed during a live VirusTotal file hash investigation.

**File:** BreakOut.exe  
**Type:** Win32 EXE  
**Size:** 2,048,000 bytes

**SHA-256:**

```text
226a723ffb4a91d9950a8b266167c5b354ab0db1dc225578494917fe53867ef2
```

**VirusTotal results:**

| Intelligence Field | Result |
|---|---|
| Malicious detections | 52 |
| Suspicious detections | 0 |
| Harmless detections | 0 |
| Undetected | 10 |
| Reputation | -171 |
| ARGUS assessment | Review required |

These findings demonstrate ARGUS's ability to retrieve and summarize real-world file intelligence.

VirusTotal detections are intelligence signals, not definitive proof of malicious activity. Findings should be evaluated alongside endpoint telemetry, file behavior, and investigation context.

## Automated Testing

Project ARGUS uses `pytest` to validate core functionality.

Run the complete test suite:

```powershell
python -m pytest -v
```

**Current verified baseline: 16 passing tests.**

Tests cover:

- IPv4 and IPv6 classification.
- Invalid IP address handling.
- MD5, SHA-1, and SHA-256 identification.
- Invalid file hash detection.
- Mocked VirusTotal API requests.
- HTTP 429 rate-limit error propagation.
- IP intelligence summarization.
- File intelligence summarization.

External HTTP requests are mocked during unit testing to avoid unnecessary API usage.

Interactive CLI behavior has also been manually tested.

## Security Considerations

- API keys are retrieved from environment variables.
- Credentials must never be committed to Git.
- Virtual environments should remain excluded from version control.
- VirusTotal results require analyst interpretation.
- External intelligence requests should be performed only for authorized investigations.
- HTTP failures and API rate limits must be handled safely.

## Development Roadmap

### Completed
- [x] Establish Python project structure and Git repository.
- [x] Implement IP address classification.
- [x] Develop VirusTotal IP lookup functions.
- [x] Implement MD5, SHA-1, and SHA-256 identification.
- [x] Develop VirusTotal file hash enrichment.
- [x] Generate structured intelligence summaries.
- [x] Implement HTTP error handling.
- [x] Build an interactive investigation menu.
- [x] Validate live VirusTotal file intelligence retrieval.
- [x] Establish 16 passing automated tests.

### Planned
- [ ] Implement automated CLI integration tests.
- [ ] Add VirusTotal IP enrichment to the CLI.
- [ ] Export investigation results to JSON.
- [ ] Implement domain and URL intelligence analysis.
- [ ] Integrate additional intelligence sources, including AbuseIPDB.
- [ ] Develop explainable indicator risk scoring.
- [ ] Generate consolidated investigation reports.
- [ ] Introduce GitHub Actions continuous integration.
- [ ] Implement dependency vulnerability scanning and SBOM generation.
- [ ] Explore Microsoft Sentinel and Azure integration.

## Engineering Objectives

Project ARGUS demonstrates hands-on development in:

- Python programming and modular architecture.
- REST API integration.
- JSON parsing and structured reporting.
- Threat intelligence enrichment.
- SOC investigation workflows.
- Automated testing and mocking.
- Exception handling.
- Secure credential management.
- Git version control and technical documentation.

## Project Status

**Active Development — File Hash Intelligence and Interactive CLI Milestones Complete**

Project ARGUS is an evolving security engineering portfolio project. Future development will focus on broader indicator coverage, investigation automation, reporting, and cloud security integration.