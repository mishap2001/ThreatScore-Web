# ThreatScore Web

ThreatScore Web is a local Windows threat-intelligence dashboard for triaging
IOCs with source enrichment, AI-assisted analysis, history, chat, and exports.

Paste an IP address, domain, URL, or file hash. ThreatScore queries configured
threat-intelligence sources, summarizes the evidence, and produces a concise
SOC-style verdict you can act on.

> Private/local-first by design: the app runs on `127.0.0.1`, stores keys
> locally, and only contacts the external services you configure.

## Highlights

- Local browser UI served from a Python standard-library backend
- IP, domain, URL, MD5, SHA1, and SHA256 IOC support
- Automatic refanging for common defanged IOC formats
- Multi-source threat-intelligence enrichment
- OpenAI-generated SOC verdicts and recommended actions
- Optional Gemini OSINT enrichment
- Follow-up IOC chat for investigation questions
- SIEM detection generation prompts
- Bulk scan mode
- Local scan history and cached results
- Markdown report export with defanged IOC titles
- CSV history export
- Windows DPAPI-encrypted API key storage
- Optional standalone Windows `.exe` build

## Supported IOC types

| IOC type | Examples |
| --- | --- |
| IP address | `8.8.8.8`, IPv6 addresses |
| Domain | `example.com` |
| URL | `https://example.com/path` |
| Hash | MD5, SHA1, SHA256 |

ThreatScore also refangs common formats such as:

- `hxxp://example[.]com`
- `example(dot)com`
- `user[at]example[.]com`

## Intelligence sources

ThreatScore uses whichever API keys you configure. Sources without keys are
skipped automatically.

| Source | Coverage |
| --- | --- |
| VirusTotal | IPs, domains, URLs, hashes |
| AlienVault OTX | IPs, domains, URLs, hashes |
| AbuseIPDB | IP reputation |
| IPInfo | IP ASN and location context |
| GreyNoise | Internet scanning/noise context |
| urlscan.io | Domain and URL scan history |
| Cloudflare URL Scanner | URL scan context |
| ThreatYeti / alphaMountain | Domain risk context |
| MalwareBazaar | Malware hash context |
| OpenAI | Final analysis and follow-up chat |
| Gemini | OSINT enrichment and fresh context |

## Quick start

### Requirements

- Windows
- Python 3.10 or newer
- API keys for the sources you want to use

No Python packages are required to run the app.

### Run locally

Double-click:

```text
start.cmd
```

Or run:

```powershell
python server.py
```

Open:

```text
http://localhost:8736
```

If port `8736` is busy, ThreatScore automatically tries later ports.

## First-time setup

1. Start ThreatScore.
2. Open Settings with the gear button.
3. Add API keys for the sources you want.
4. Click **Test all keys**.
5. Pick the OpenAI model and temperature.
6. Disable any sources you do not want to query.

Recommended minimum setup:

- VirusTotal API key
- OpenAI API key

More sources produce better context, especially for reputation, infrastructure,
malware hashes, and OSINT-heavy investigations.

## Build a standalone EXE

Double-click:

```text
build-exe.cmd
```

The script installs PyInstaller if needed and creates:

```text
dist\ThreatScore.exe
```

That executable can run on Windows machines without Python installed.

Note: one-file PyInstaller apps can be flagged by antivirus tools as false
positives because they are packed executables. If that happens, use the Python
run mode or allow the binary only if you trust your own build.

## How it works

ThreatScore starts a local HTTP server and serves `ui.html`. The UI talks to
the backend through local API routes and a Server-Sent Events scan stream.

During a scan, the backend:

1. Refangs and classifies the IOC.
2. Runs the relevant enabled sources.
3. Normalizes source results into a compact intelligence summary.
4. Optionally adds Gemini OSINT context.
5. Sends the summary to OpenAI for a SOC-style verdict.
6. Stores the result locally for history, chat, and exports.

## Follow-up chat

After a scan, IOC Chat can answer investigation questions using the current scan
context. Built-in prompts include:

- Known threat actor or campaign context
- MITRE ATT&CK techniques
- SIEM detection rules
- False-positive analysis
- Related IOC hunting
- Incident report summary
- Organizational risk summary

Supported SIEM targets:

- Splunk SPL
- IBM QRadar AQL
- Microsoft Sentinel KQL
- Elastic / EQL
- Chronicle / YARA-L
- Sumo Logic

## Local data

ThreatScore stores local app data in:

```text
%APPDATA%\ThreatScore
```

| File | Purpose |
| --- | --- |
| `keys.dat` | DPAPI-encrypted API key store |
| `history.json` | Recent scan history |
| `results.json` | Cached scan results |
| `chats.json` | Per-IOC chat transcripts |
| `config.json` | Preferences and source toggles |
| `ThreatScore_results.csv` | Optional auto-appended CSV output |

Do not commit or share anything from `%APPDATA%\ThreatScore`.

## Security and privacy

- The web app binds to `127.0.0.1`.
- API keys are stored locally and encrypted with Windows DPAPI.
- API keys are not part of this repository.
- Build output and caches are ignored by Git.
- IOCs and scan data are sent to the third-party sources you enable.
- OpenAI receives the normalized scan summary when AI analysis or chat is used.
- Gemini receives IOC/chat context when Gemini OSINT is enabled.

## Configuration

Use a custom port:

```powershell
set PORT=9000
python server.py
```

Prevent auto-opening the browser:

```powershell
set TS_NO_OPEN=1
python server.py
```

Available OpenAI model choices in Settings:

- `gpt-4o`
- `gpt-4o-mini`
- `gpt-4.1`
- `gpt-4.1-mini`
- `gpt-4-turbo`

Defaults:

- Model: `gpt-4o`
- Temperature: `0.2`
- Auto CSV: off
- Disabled sources: none

## Project structure

```text
.
|-- README.md
|-- build-exe.cmd
|-- secrets_store.py
|-- server.py
|-- start.cmd
`-- ui.html
```

| File | Purpose |
| --- | --- |
| `server.py` | Local server, routes, scan workflow, AI prompts, persistence |
| `ui.html` | Browser UI, settings, history, chat, reports, bulk mode |
| `secrets_store.py` | Windows DPAPI encryption for saved API keys |
| `start.cmd` | Finds Python and starts ThreatScore |
| `build-exe.cmd` | Builds a standalone EXE with PyInstaller |

## Local API

| Route | Method | Purpose |
| --- | --- | --- |
| `/` | GET | Serves the UI |
| `/api/scan?ioc=...` | GET | Runs a scan using Server-Sent Events |
| `/api/history` | GET | Returns scan history |
| `/api/result?ioc=...` | GET | Returns cached result and chat transcript |
| `/api/export.csv` | GET | Downloads scan history as CSV |
| `/api/keys` | GET/POST | Lists key status or saves/clears one key |
| `/api/keys/test` | POST | Tests configured API keys |
| `/api/keys/reset` | POST | Clears all saved keys |
| `/api/config` | GET/POST | Reads or saves preferences |
| `/api/history/clear` | POST | Clears history, cached results, and chats |
| `/api/chat` | POST | Sends a follow-up question for the current scan |

## Troubleshooting

### Python is not found

Install Python 3.10 or newer from `python.org`. During installation, enable
**Add Python to PATH**. The launcher also checks common per-user Python install
locations.

### A source is skipped

The source has no saved API key, or it is disabled in Settings.

### A key test fails

Check that the key is valid, has the required permissions, and has not hit quota
or account restrictions. Cloudflare requires both an account ID and an API token
with URL Scanner access.

### OpenAI analysis is unavailable

Add an OpenAI API key in Settings and test it. Also confirm the selected model
is available to your account.

### The browser does not open

Open the printed local URL manually, usually:

```text
http://localhost:8736
```
