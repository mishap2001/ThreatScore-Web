# ThreatScore for Windows — Python edition

The same local web app as the Node version ([../windows](../windows)), but the
server is written in **Python** instead of JavaScript. Same browser UI, same
features, same data.

It shares the Node version's data folder (`%APPDATA%\ThreatScore`), so your
API keys, history, and settings carry over automatically — the encrypted key
store is byte-compatible (Windows DPAPI).

## Two ways to run it

### A) Run with Python (no build step)
Requires **Python 3.10+** (the standard library only — no `pip install` needed).

Double-click **`start.cmd`**, or from a terminal in this folder:
```
python server.py
```
It starts on <http://localhost:8736> and opens your browser. `Ctrl+C` to stop.

### B) Standalone .exe (no Python needed on the target machine)
Double-click **`build-exe.cmd`** once. It installs PyInstaller and produces:
```
dist\ThreatScore.exe
```
That single file runs on any Windows PC by double-clicking — Python not required.

> Note: PyInstaller one-file exes are sometimes flagged by antivirus as a
> false positive (common for packed Python apps). If that happens, allow it,
> or just use option A.

## Files
| File | Purpose |
|------|---------|
| `server.py` | Local HTTP server + all scan/AI logic (stdlib only) |
| `secrets_store.py` | DPAPI-encrypted key storage via ctypes |
| `ui.html` | The browser UI (identical to the Node edition) |
| `start.cmd` | Run with Python |
| `build-exe.cmd` | Build the standalone .exe |

## Notes
- Change the port: `set PORT=9000 && python server.py` (auto-tries next ports if busy).
- `set TS_NO_OPEN=1` to stop it auto-opening the browser.
- The Node and Python editions are interchangeable but shouldn't run at the same
  time on the same port.
