# Project ARGUS

**Automated Reputation Gathering & Unified Security**

A local-first, Python-based threat intelligence enrichment and security analysis project designed to support security operations investigations.

## Overview

Project ARGUS is an evolving cybersecurity engineering project focused on automating the collection, analysis, and interpretation of threat intelligence.

The project aims to help security analysts investigate suspicious indicators, correlate intelligence from multiple sources, and produce actionable, explainable findings.

ARGUS is being developed locally to minimize infrastructure costs while emphasizing modular design, automated testing, and secure development practices.

## Current Capabilities

### IP Address Analysis
- Validates IPv4 and IPv6 addresses.
- Identifies private, globally routable, loopback, multicast, and reserved address classifications.
- Handles invalid IP input.

### VirusTotal Integration — Initial Implementation
- Constructs VirusTotal API v3 IP reputation requests.
- Supports API-key authentication through a function parameter.
- Retrieves and returns JSON responses.
- Raises exceptions for unsuccessful HTTP responses.
- Includes mocked tests for successful requests and HTTP 429 rate-limit responses.

**Status:** Unit-tested integration module. Live API connectivity and end-to-end enrichment are not yet implemented or validated.

## Project Structure

```text
project-argus/
├── argus/
│   ├── __init__.py
│   ├── main.py
│   ├── ip_analyzer.py
│   └── intelligence/
│       ├── __init__.py
│       └── virustotal.py
├── tests/
│   ├── test_ip_analyzer.py
│   └── test_virustotal.py
├── .gitignore
├── README.md
└── requirements.txt
```

## Getting Started

### Prerequisites

- Python 3.13
- Git
- A terminal or Python-compatible development environment

### Installation

Clone the repository:

```powershell
git clone https://github.com/keeegz/project-argus.git
cd project-argus
```

Create a virtual environment:

```powershell
python -m venv .venv
```

Activate it in PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

### Run the IP Analyzer

```powershell
python -m argus.main
```

The CLI prompts for an IP address and displays its classification.

## Automated Testing

ARGUS uses `pytest` to validate existing functionality and detect regressions.

Run the full test suite:

```powershell
python -m pytest -v
```

**Current baseline: 6 passing tests.**

Tests cover IP classification, invalid input handling, simulated VirusTotal API success, and HTTP 429 error propagation.

External HTTP requests are mocked during unit testing. Live provider behavior requires separate integration testing.

## Security Considerations

- API credentials must never be committed to source control.
- Local virtual environments and environment files are excluded through `.gitignore`.
- External threat intelligence requests should be restricted to appropriate indicators.
- Future enhancements will include dependency vulnerability scanning and SBOM generation.

## Development Roadmap

- [x] Initialize local Python environment and Git repository.
- [x] Implement IP address classification.
- [x] Establish automated unit testing.
- [x] Create initial VirusTotal integration.
- [x] Publish project to GitHub.
- [ ] Implement secure API credential loading.
- [ ] Validate live VirusTotal API connectivity.
- [ ] Add structured intelligence parsing and enrichment.
- [ ] Implement graceful error handling and rate-limit management.
- [ ] Integrate additional intelligence sources, including AbuseIPDB.
- [ ] Develop explainable indicator risk scoring.
- [ ] Generate consolidated analyst investigation reports.
- [ ] Implement SBOM generation and dependency vulnerability scanning.
- [ ] Introduce automated CI security and regression checks.

## Engineering Objectives

ARGUS is intended to demonstrate practical experience in:

- Python development and modular software architecture.
- REST API integration and JSON processing.
- Threat intelligence enrichment and security operations automation.
- Automated testing and error handling.
- Secure software development and supply chain visibility.
- Version control and technical documentation.

## Project Status

**Active development — Milestone 2 complete.**

The current implementation provides a tested