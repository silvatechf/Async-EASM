# Async EASM Pipeline

A Python learning project for asynchronous external attack-surface discovery. It performs HTTP requests against a supplied target list, records basic response and header observations, and can pass a JSON report to an optional Nuclei orchestration step.

> **Authorized use only.** Run active checks only against assets you own or have explicit written permission to assess. Start with a small lab target list. This project is an educational prototype, not a production EASM platform or a comprehensive vulnerability scanner.

## Capabilities

- Asynchronous HTTP requests with a configurable concurrency limit and retry attempts.
- Basic response-title and security-header heuristics.
- JSON output for reachable targets.
- Optional Nuclei invocation using structured subprocess arguments and a limited tag set.

## Requirements

- Python 3.10 or newer recommended.
- Python dependency: `aiohttp` (see `requirements.txt`).
- Optional for the second stage: ProjectDiscovery Nuclei installed and available on `PATH`.

## Run locally (Windows PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Create a text file such as `targets.txt` containing one authorized hostname or URL per line. Use only systems within your approved scope.

```powershell
python engine_easm.py targets.txt
```

The first stage writes `robust_exposure_report.json` in the current directory. To run the optional second stage:

```powershell
python vuln_orchestrator.py robust_exposure_report.json
```

The second stage requires Nuclei separately. Review the tool's output and options before use; a successful process exit does not mean a target is safe or vulnerable.

## Important limitations

- Findings are simple heuristics, not proof of vulnerabilities. A missing HSTS header or a title containing `admin` is not, by itself, a confirmed security issue.
- The implementation does not provide DNS asset discovery, authenticated scanning, durable storage, a user interface, or comprehensive WAF detection.
- Target validation, redirect behavior, output naming, and explicit target-scope enforcement need further hardening before broader use.
- TLS certificate verification is enabled by default. Do not disable it to work around certificate errors; investigate and fix the trust configuration instead.
- Do not use results as a substitute for manual validation or an authorized security assessment.

## Project status

Learning lab; automated tests and CI are not currently included. Run against a controlled lab and validate behavior before relying on any result.

## License

See `LICENSE.md` for the repository's license.

## Contact

[LinkedIn](https://www.linkedin.com/in/fernando-silva-83b155a4/)
