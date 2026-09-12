# Async EASM Pipeline & Vulnerability Orchestrator 

An enterprise-grade, asynchronous External Attack Surface Management (EASM) engine built in Python. Designed to solve the pain of noisy reconnaissance, false positives, and brittle shell scripts by providing a resilient, concurrent pipeline for Red Teams and Blue Teams.

## 🎯 The Problem It Solves
Traditional reconnaissance tools often trigger Web Application Firewalls (WAFs), crash under network instability, and dump raw data that requires hours of manual triage. This pipeline automates the discovery, filters out dead hosts, extracts context (Tech Stack, Shadow IT), and safely orchestrates vulnerability scanning.

## ⚙️ Core Architecture & Features
- **Asynchronous Engine:** Utilizes \iohttp\ and \syncio\ to process hundreds of targets concurrently without CPU blocking.
- **Resilient Networking:** Implements Exponential Backoff and User-Agent rotation to survive rate-limits, packet loss, and basic WAF protections.
- **Defensive Heuristics:** Automatically detects Directory Listing, exposed test environments (Shadow IT), and missing security headers.
- **Safe Orchestration:** Parses JSON intelligence to dynamically adjust the aggressiveness of vulnerability scanners (like ProjectDiscovery's Nuclei) based on WAF presence.
- **Secure Subprocessing:** Eliminates Command Injection vulnerabilities by executing external binaries via strict array parameterization.

## 🚀 Usage

### 1. Installation

### Create an isolated virtual environment
```sh
python -m venv easm_env
source easm_env/bin/activate  # On Windows: .\easm_env\Scripts\activate
```


### Install async dependencies
```sh
pip install -r requirements.txt

```
### 2. Execution Pipeline

### Step 1: Run the passive/active reconnaissance engine
```sh
python engine_easm.py targets.txt
```
### Step 2: Orchestrate vulnerability scanning based on contextual intelligence
```sh
python vuln_orchestrator.py robust_exposure_report.json
```


## ⚖️ Ethical Disclaimer & Rules of Engagement
This toolkit is developed strictly for **educational purposes, authorized penetration testing, and defensive posture validation**. 
The developers assume no liability and are not responsible for any misuse or damage caused by this program. 

## 🚫 Never execute active scans against infrastructure without explicit, written consent from the asset owner.




## 👨‍💻 Author / Contact
* **Fernando Silva** - [Connect on LinkedIn](https://www.linkedin.com/in/fernando-silva-83b155a4/)
