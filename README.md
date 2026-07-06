# ThreatScore Web

ThreatScore Web is a local Windows threat-intelligence workbench for quickly
triaging indicators of compromise (IOCs). Paste an IP, domain, URL, or file
hash, and ThreatScore pulls together source intelligence, AI analysis, scan
history, exports, and follow-up investigation prompts in one browser UI.

This Python edition runs locally on `127.0.0.1`, uses only the Python standard
library at runtime, and stores API keys encrypted with Windows DPAPI under the
current Windows user.

## What it does

- Scans IP addresses, domains, URLs, and MD5/SHA1/SHA256 hashes.
- Refangs common defanged IOC formats such as `hxxp://`, `[.]`, `(dot)`, and
  `[at]`.
- Queries multiple threat-intelligence services and normalizes the results.
- Produces a concise SOC-style verdict using OpenAI.
- Adds optional Gemini OSINT context before analysis and follow-up answers.
- Keeps local scan history, per-IOC result details, and per-IOC chat history.
- Supports bulk scanning, one IOC per line.
- Exports markdown reports with defanged IOCs.
- Exports scan history as CSV.
- Generates follow-up answers and SIEM detections for common platforms.
- Lets you disable noisy sources without deleting their saved keys.

## Supported intelligence sources

ThreatScore uses whichever API keys you add in Settings. Missing keys are simply
skipped.

| Source | Used for | Key name in app |
| --- | --- | --- |
| VirusTotal | IPs, domains, URLs, hashes | VirusTotal API Key |
| AlienVault OTX | IPs, domains, URLs, hashes | OTX API Key |
| AbuseIPDB | IP reputation | AbuseIPDB API Key |
| IPInfo | IP ASN and location context | IPInfo API Key |
| GreyNoise | Internet scanning/noise context | GreyNoise API Key |
| urlscan.io | Domain and URL scan history | urlscan.io API Key |
| Cloudflare URL Scanner | URL scan context | Cloudflare Account ID and API Token |
| ThreatYeti / alphaMountain | Domain risk context | ThreatYeti API Key |
| MalwareBazaar | Hash malware context | MalwareBazaar API Key |
| OpenAI | Final SOC analysis and chat | OpenAI API Key |
| Gemini | OSINT enrichment and fresh web context for chat | Gemini API Key |

## Quick start

### Option 1: Run with Python

Requires Windows and Python 3.10 or newer.

Double-click:

```text
start.cmd
```

Or run from this folder:

```powershell
python server.py
```

ThreatScore starts at:

```text
http://localhost:8736
```

If port `8736` is busy, the server automatically tries the next few ports.

### Option 2: Build a standalone EXE

Double-click:

```text
build-exe.cmd
```

The build script installs PyInstaller if needed and creates:

```text
dist\ThreatScore.exe
```

The EXE can run on another Windows machine without requiring Python.

Note: one-file PyInstaller applications are sometimes flagged by antivirus
tools as false positives because they are packed executables. If that happens,
use the Python run mode or allow the built executable if you trust your own
build.

## First setup

1. Start the app.
2. Open Settings with the gear button in the lower-left sidebar.
3. Add the API keys you want to use.
4. Click "Test all keys" to verify them.
5. Set your preferred OpenAI model and temperature.
6. Optionally disable sources you do not want to query.

Recommended minimum useful setup:

- VirusTotal API key
- OpenAI API key

Additional sources improve context and confidence, especially for IP reputation,
URL infrastructure, malware hashes, and OSINT-heavy investigations.

## Workflow

1. Paste an IOC into the scan box.
2. ThreatScore detects the IOC type and runs the relevant sources.
3. Source cards update as each service responds.
4. OpenAI produces an operational verdict and recommended actions.
5. Ask follow-up questions in IOC Chat.
6. Export a markdown report or download CSV history when needed.

Built-in follow-up prompts include:

- Known threat actor or campaign context
- MITRE ATT&CK techniques
- SIEM detection generation
- False-positive analysis
- Related IOC hunting
- Incident report summary
- Organizational risk summary

Supported SIEM output targets:

- Splunk SPL
- IBM QRadar AQL
- Microsoft Sentinel KQL
- Elastic / EQL
- Chronicle / YARA-L
- Sumo Logic

## Local data and key storage

ThreatScore keeps data in:

```text
%APPDATA%\ThreatScore
```

Files created there include:

| File | Purpose |
| --- | --- |
| `keys.dat` | Encrypted API key store |
| `history.json` | Recent scan history |
| `results.json` | Cached scan results |
| `chats.json` | Per-IOC chat transcripts |
| `config.json` | Model, temperature, source toggles, CSV setting |
| `ThreatScore_results.csv` | Optional auto-appended CSV output |

API keys are encrypted with Windows DPAPI using the current Windows user scope.
That means the key file is intended to be readable only by the same Windows user
on the same machine profile. Do not upload `keys.dat` or anything from
`%APPDATA%\ThreatScore`.

## Privacy and security notes

- The web app is served locally from `127.0.0.1`.
- API keys are not included in this repository.
- Generated build output is ignored by Git.
- IOCs and scan data are sent to the third-party services whose keys you enable.
- OpenAI receives the normalized scan summary when AI analysis or chat is used.
- Gemini receives the IOC or chat question when Gemini OSINT is enabled.
- Exported markdown reports defang the IOC in the report title.

## Configuration

Set a custom port:

```powershell
set PORT=9000
python server.py
```

Prevent the browser from opening automatically:

```powershell
set TS_NO_OPEN=1
python server.py
```

The app currently allows these OpenAI model names from Settings:

- `gpt-4o`
- `gpt-4o-mini`
- `gpt-4.1`
- `gpt-4.1-mini`
- `gpt-4-turbo`

Default settings:

- Model: `gpt-4o`
- Temperature: `0.2`
- Auto CSV: off
- Disabled sources: none

## Project files

| File | Purpose |
| --- | --- |
| `server.py` | Local HTTP server, API routes, scan logic, AI prompts, persistence |
| `ui.html` | Browser UI, scan workflow, settings, chat, export behavior |
| `secrets_store.py` | Windows DPAPI key encryption and decryption |
| `start.cmd` | Finds Python 3.10+ and starts the server |
| `build-exe.cmd` | Builds `dist\ThreatScore.exe` with PyInstaller |
| `.gitignore` | Keeps generated files, caches, archives, and secret-like files out of Git |

## API routes

These routes are served locally by `server.py`:

| Route | Method | Purpose |
| --- | --- | --- |
| `/` | GET | Serves the UI |
| `/api/scan?ioc=...` | GET | Runs a scan over Server-Sent Events |
| `/api/history` | GET | Returns scan history |
| `/api/result?ioc=...` | GET | Returns a cached result and chat transcript |
| `/api/export.csv` | GET | Downloads scan history as CSV |
| `/api/keys` | GET/POST | Lists key status or saves/clears one key |
| `/api/keys/test` | POST | Tests configured API keys |
| `/api/keys/reset` | POST | Clears all saved keys |
| `/api/config` | GET/POST | Reads or saves app preferences |
| `/api/history/clear` | POST | Clears history, cached results, and chats |
| `/api/chat` | POST | Sends a follow-up question for the current scan |

## Repository upload checklist

Upload these files to GitHub:

- `.gitignore`
- `README.md`
- `build-exe.cmd`
- `secrets_store.py`
- `server.py`
- `start.cmd`
- `ui.html`

Do not upload:

- `.git/`
- `dist/`
- `build/`
- `__pycache__/`
- `*.pyc`
- `.env` files
- `*.key`, `*.pem`, `*.p12`, or `*.pfx`
- zip or rar archives
- anything from `%APPDATA%\ThreatScore`

## Troubleshooting

### Python is not found

Install Python 3.10 or newer from `python.org` and enable "Add Python to PATH"
during installation. `start.cmd` also checks common per-user Python install
locations.

### A source says skipped

That source does not have a saved key, or it was disabled in Settings.

### A key test fails

Check that the key is valid, has the required product permissions, and has not
hit quota or account restrictions. Cloudflare requires both the account ID and
an API token with URL Scanner access.

### OpenAI analysis is unavailable

Add an OpenAI API key in Settings and test it. If the key is valid, confirm the
selected model is available to your account.

### Browser does not open

Open the printed local URL manually. By default it is:

```text
http://localhost:8736
```

### The port is already in use

ThreatScore automatically tries later ports. You can also set `PORT` manually.

## License

No license file is included yet. Until a license is added, treat this as private
source code.
