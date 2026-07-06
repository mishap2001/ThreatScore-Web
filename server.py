#!/usr/bin/env python3
"""ThreatScore for Windows - Python edition.

Same local web app as the Node version (serves ui.html, same API), implemented
with the Python standard library only (no pip packages needed to run).
Run:  python server.py    (or double-click start.cmd)
"""

import os
import re
import sys
import json
import time
import base64
import ssl
import socket
import threading
import webbrowser
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from concurrent.futures import ThreadPoolExecutor

import secrets_store as secrets

# Locate ui.html whether running as a script or a PyInstaller one-file exe.
BASE_DIR = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
UI_PATH = os.path.join(BASE_DIR, "ui.html")

KEY_NAMES = {
    "VT_API": "VirusTotal API Key",
    "OTX_API": "OTX (AlienVault) API Key",
    "ABUSEIPDB": "AbuseIPDB API Key",
    "IPINFO": "IPInfo API Key",
    "GREYNOISE": "GreyNoise API Key",
    "URLSCAN": "urlscan.io API Key",
    "CF_ACCOUNT_ID": "Cloudflare Account ID",
    "CF_TOKEN": "Cloudflare API Token",
    "TY_API": "ThreatYeti (alphaMountain) API Key",
    "MB_API": "MalwareBazaar API Key",
    "OPENAI": "OpenAI API Key",
    "GEMINI": "Gemini API Key",
}

DATA_DIR = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "ThreatScore")
HIST_PATH = os.path.join(DATA_DIR, "history.json")
RESULTS_PATH = os.path.join(DATA_DIR, "results.json")
CHATS_PATH = os.path.join(DATA_DIR, "chats.json")
CONFIG_PATH = os.path.join(DATA_DIR, "config.json")
CSV_PATH = os.path.join(DATA_DIR, "ThreatScore_results.csv")

TOGGLEABLE_SOURCES = ["IPInfo", "VirusTotal", "AbuseIPDB", "GreyNoise", "OTX",
                      "urlscan", "Cloudflare", "ThreatYeti", "MalwareBazaar", "Gemini OSINT"]
DEFAULT_CONFIG = {"model": "gpt-4o", "temperature": 0.2, "autoCsv": False, "disabledSources": []}
ALLOWED_MODELS = ["gpt-4o", "gpt-4o-mini", "gpt-4.1", "gpt-4.1-mini", "gpt-4-turbo"]

_lock = threading.Lock()
_ssl_ctx = ssl.create_default_context()


# ── persistence ──────────────────────────────────────────────────────────────
def read_json(path, fallback):
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return fallback


def write_json(path, data):
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except Exception:
        pass


keys = secrets.load()
config = {**DEFAULT_CONFIG, **read_json(CONFIG_PATH, {})}
history = read_json(HIST_PATH, [])
results = read_json(RESULTS_PATH, {})
chats = read_json(CHATS_PATH, {})
current_scan = None
if not isinstance(history, list):
    history = []
if not isinstance(results, dict):
    results = {}
if not isinstance(chats, dict):
    chats = {}


def save_history():
    write_json(HIST_PATH, history)


def save_results():
    write_json(RESULTS_PATH, results)


def prune_results():
    ks = list(results.keys())
    if len(ks) > 120:
        for k in ks[:len(ks) - 120]:
            results.pop(k, None)


def save_chats():
    write_json(CHATS_PATH, chats)


def get_chat(ioc):
    if ioc not in chats:
        chats[ioc] = {"messages": [], "transcript": []}
    return chats[ioc]


def prune_chats():
    ks = list(chats.keys())
    if len(ks) > 120:
        for k in ks[:len(ks) - 120]:
            chats.pop(k, None)


def save_config():
    write_json(CONFIG_PATH, config)


def is_disabled(name):
    return name in config.get("disabledSources", [])


def now_stamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def csv_escape(s):
    return '"' + str("" if s is None else s).replace('"', '""') + '"'


def history_to_csv():
    rows = ["Timestamp,Type,IOC,Verdict"]
    for h in history:
        rows.append(",".join(csv_escape(x) for x in [h.get("at") or h.get("ts"), h.get("type"), h.get("ioc"), h.get("verdict")]))
    return "\r\n".join(rows) + "\r\n"


def append_csv(entry):
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        if not os.path.exists(CSV_PATH):
            with open(CSV_PATH, "w", encoding="utf-8") as f:
                f.write("Timestamp,Type,IOC,Verdict\r\n")
        with open(CSV_PATH, "a", encoding="utf-8") as f:
            f.write(",".join(csv_escape(x) for x in [entry["at"], entry["type"], entry["ioc"], entry["verdict"]]) + "\r\n")
    except Exception:
        pass


# ── HTTP helper ──────────────────────────────────────────────────────────────
def extract_api_error(data):
    if not data:
        return ""
    if isinstance(data, str):
        return data
    if isinstance(data, dict):
        err = data.get("error")
        if isinstance(err, str):
            return err
        if isinstance(err, dict):
            if err.get("message"):
                return err["message"]
            if err.get("code"):
                return str(err["code"])
        errs = data.get("errors")
        if isinstance(errs, list) and errs:
            if isinstance(errs[0], dict):
                if errs[0].get("detail"):
                    return errs[0]["detail"]
                if errs[0].get("title"):
                    return errs[0]["title"]
        for k in ("message", "detail", "query_status"):
            if data.get(k):
                return data[k]
    return ""


def request_json(url, method="GET", headers=None, body=None, timeout=60):
    headers = dict(headers or {})
    data = None
    if body is not None:
        data = body.encode("utf-8") if isinstance(body, str) else body
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx) as resp:
            status = resp.status
            text = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        status = e.code
        try:
            text = e.read().decode("utf-8", "replace")
        except Exception:
            text = ""
    except (socket.timeout, TimeoutError):
        return {"ok": False, "status": "request_error", "error": "timeout"}
    except Exception as e:
        return {"ok": False, "status": "request_error", "error": str(e)}

    try:
        d = json.loads(text) if text else {}
    except Exception:
        return {"ok": False, "status": status, "error": "invalid json", "body": text[:400]}

    if status < 200 or status >= 300:
        return {"ok": False, "status": status, "error": extract_api_error(d) or ("HTTP %s" % status), "body": d}
    return {"ok": True, "status": status, "data": d}


def api_error(r, name):
    return {"error": name + ": " + (r.get("error") or "failed"), "status": r.get("status") or "unknown"}


def g(d, *path, default=None):
    """Safe nested get: g(data, 'a', 'b', default=0)."""
    cur = d
    for p in path:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        elif isinstance(cur, list) and isinstance(p, int) and 0 <= p < len(cur):
            cur = cur[p]
        else:
            return default
    return cur if cur is not None else default


# ── IOC helpers ──────────────────────────────────────────────────────────────
def refang(s):
    s = str(s or "").strip()
    s = re.sub(r"hxxp", "http", s, flags=re.I)
    s = re.sub(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", ".", s, flags=re.I)
    s = s.replace("[:]", ":").replace("[//]", "//")
    s = re.sub(r"\[at\]|\(at\)", "@", s, flags=re.I)
    return s.strip()


def detect_type(s):
    s = str(s or "").strip()
    if re.match(r"^https?://", s, re.I):
        return "URL"
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", s):
        if all(0 <= int(p) <= 255 for p in s.split(".")):
            return "IP"
    if re.match(r"^[0-9a-fA-F:]+$", s) and ":" in s:
        return "IP"
    if re.match(r"^[a-fA-F0-9]{32}$", s) or re.match(r"^[a-fA-F0-9]{40}$", s) or re.match(r"^[a-fA-F0-9]{64}$", s):
        return "HASH"
    if re.match(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", s):
        return "DOMAIN"
    return "UNKNOWN"


def host_from_url(s):
    m = re.match(r"^https?://([^/?#]+)", str(s), re.I)
    if not m:
        return s
    return re.sub(r":\d+$", "", re.sub(r"^[^@]*@", "", m.group(1)))


def sys_prompt(t):
    if t == "IP":
        return "Senior SOC analyst. Analyze IP IOCs. Be direct, operational, concise."
    if t in ("DOMAIN", "URL"):
        return "Senior SOC analyst. Analyze URL/domain IOCs. Be direct, concise."
    if t == "HASH":
        return "Senior malware triage analyst. Analyze file hashes. Be direct, concise."
    return "Senior SOC analyst. Be concise."


def user_prompt(t, ioc, summary):
    head = ("Analyze this " + t + " IOC.\nTarget: " + ioc + "\n\nIntelligence:\n" + summary +
            "\n\nRules: <=1800 chars, no generic wording, no unsupported speculation.\n\nOutput exactly:\n")
    if t == "HASH":
        return head + (
            "Verdict: <clean/low risk/suspicious/malicious + file role>\n"
            "Why: <1-2 lines strongest evidence>\n"
            "Associated activity: <malware/PUA/loader/etc>\n"
            "Likely behavior: <expected file behavior>\n"
            "Exploit pattern: <delivery/execution pattern or none>\n"
            "Threat attribution: <1 line>\n"
            "Action: <2-3 SOC actions>")
    infra = ("Infrastructure: <country, ASN, VPS/cloud/proxy context>\n" if t == "IP"
             else "Infrastructure: <hosting country, ASN, server/TLD>\n")
    return head + (
        "Verdict: <clean/low risk/suspicious/malicious + role>\n" + infra +
        "Why: <1-2 lines strongest evidence>\n"
        "Associated activity: <behavior>\n"
        "Likely behavior: <how it is used>\n"
        "Exploit pattern: <or none>\n"
        "Threat attribution: <1 line>\n"
        "Action: <2-3 SOC actions>")


def classify_verdict(s):
    s = str(s or "").lower()
    if re.search(r"malicious|high risk|\bhigh\b", s):
        return "HIGH"
    if re.search(r"suspicious|\bmedium\b", s):
        return "MEDIUM"
    if re.search(r"\bclean\b|benign|harmless|not malicious|legitimate", s):
        return "CLEAN"
    if re.search(r"low risk|\blow\b", s):
        return "LOW"
    return None


def parse_verdict(t):
    if not t:
        return "UNKNOWN"
    for line in str(t).split("\n"):
        line = re.sub(r"[*_`#>]", "", line).strip()
        if re.match(r"^verdict\s*[:\-]", line, re.I):
            after = re.split(r"[.;]", re.sub(r"^verdict\s*[:\-]\s*", "", line, flags=re.I))[0]
            v = classify_verdict(after)
            if v:
                return v
    return classify_verdict(t) or "UNKNOWN"


def sleep(seconds):
    time.sleep(seconds)


# ── scanners ─────────────────────────────────────────────────────────────────
def scan_vt(ioc, type_):
    if not keys.get("VT_API"):
        return {"skipped": True}
    h = {"x-apikey": keys["VT_API"]}
    if type_ == "URL":
        sub = request_json("https://www.virustotal.com/api/v3/urls", "POST",
                           {**h, "Content-Type": "application/x-www-form-urlencoded"},
                           "url=" + urllib.parse.quote(ioc, safe=""), 60)
        if not sub["ok"]:
            return api_error(sub, "VT submit")
        sid = g(sub, "data", "data", "id")
        if not sid:
            return {"error": "VT no analysis ID", "status": sub["status"]}
        for _ in range(6):
            sleep(2.5)
            poll = request_json("https://www.virustotal.com/api/v3/analyses/" + urllib.parse.quote(sid, safe=""), "GET", h, None, 60)
            if not poll["ok"]:
                return api_error(poll, "VT analysis")
            attr = g(poll, "data", "data", "attributes", default={})
            if attr.get("status") == "completed":
                st = attr.get("stats", {})
                return {"malicious": st.get("malicious", 0), "suspicious": st.get("suspicious", 0),
                        "harmless": st.get("harmless", 0), "undetected": st.get("undetected", 0), "status": "completed"}
        return {"error": "VT analysis timeout", "status": "timeout"}

    if type_ == "IP":
        url = "https://www.virustotal.com/api/v3/ip_addresses/" + urllib.parse.quote(ioc, safe="")
    elif type_ == "DOMAIN":
        url = "https://www.virustotal.com/api/v3/domains/" + urllib.parse.quote(ioc, safe="")
    else:
        url = "https://www.virustotal.com/api/v3/files/" + urllib.parse.quote(ioc, safe="")

    r = request_json(url, "GET", h, None, 60)
    if not r["ok"]:
        return api_error(r, "VT")
    a = g(r, "data", "data", "attributes", default=None)
    if a is None:
        return {"error": "VT no data", "status": r["status"]}
    st = a.get("last_analysis_stats", {})
    out = {"malicious": st.get("malicious", 0), "suspicious": st.get("suspicious", 0),
           "harmless": st.get("harmless", 0), "undetected": st.get("undetected", 0),
           "reputation": a.get("reputation") if a.get("reputation") is not None else "N/A", "status": r["status"]}
    if type_ == "IP":
        out.update({"asn": a.get("asn", "N/A"), "as_owner": a.get("as_owner", "N/A"),
                    "country": a.get("country", "N/A"), "network": a.get("network", "N/A")})
    if type_ == "DOMAIN":
        out.update({"tld": a.get("tld", "N/A"), "creation": a.get("creation_date", "N/A"),
                    "categories": ", ".join(map(str, (a.get("categories") or {}).values())) or "N/A"})
    if type_ == "HASH":
        ptc = a.get("popular_threat_classification") or {}
        out.update({"md5": a.get("md5", "N/A"), "sha1": a.get("sha1", "N/A"), "sha256": a.get("sha256", "N/A"),
                    "filetype": a.get("type_description", "N/A"), "size": a.get("size", "N/A"),
                    "family": ptc.get("suggested_threat_label", "N/A"), "tags": ", ".join(a.get("tags") or []) or "N/A"})
    return out


def scan_abuseipdb(ip):
    if not keys.get("ABUSEIPDB"):
        return {"skipped": True}
    r = request_json("https://api.abuseipdb.com/api/v2/check?ipAddress=" + urllib.parse.quote(ip, safe="") + "&maxAgeInDays=90",
                     "GET", {"Key": keys["ABUSEIPDB"], "Accept": "application/json"}, None, 60)
    if not r["ok"]:
        return api_error(r, "AbuseIPDB")
    d = g(r, "data", "data", default=None)
    if d is None:
        return {"error": "AbuseIPDB no data", "status": r["status"]}
    return {"score": d.get("abuseConfidenceScore", 0), "reports": d.get("totalReports", 0),
            "users": d.get("numDistinctUsers", 0), "is_tor": d.get("isTor", False),
            "usage": d.get("usageType", "N/A"), "isp": d.get("isp", "N/A"),
            "country": d.get("countryCode", "N/A"), "last_reported": d.get("lastReportedAt", "N/A"), "status": r["status"]}


def scan_ipinfo(ip):
    if not keys.get("IPINFO"):
        return {"skipped": True}
    r = request_json("https://api.ipinfo.io/lite/" + urllib.parse.quote(ip, safe="") + "?token=" + urllib.parse.quote(keys["IPINFO"], safe=""), "GET", None, None, 60)
    if not r["ok"]:
        return api_error(r, "IPInfo")
    d = r["data"] or {}
    return {"as_name": d.get("as_name", "N/A"), "country": d.get("country", "N/A"),
            "cc": d.get("country_code", "N/A"), "continent": d.get("continent", "N/A"), "status": r["status"]}


def scan_greynoise(ip):
    if not keys.get("GREYNOISE"):
        return {"skipped": True}
    r = request_json("https://api.greynoise.io/v3/community/" + urllib.parse.quote(ip, safe=""), "GET", {"key": keys["GREYNOISE"]}, None, 60)
    if not r["ok"]:
        if r["status"] == 404:
            return {"noise": False, "riot": False, "classification": "unknown", "name": "not observed", "status": 404}
        return api_error(r, "GreyNoise")
    d = r["data"] or {}
    return {"noise": d.get("noise", False), "riot": d.get("riot", False),
            "classification": d.get("classification", "unknown"), "name": d.get("name", "N/A"), "status": r["status"]}


def scan_otx(ioc, type_):
    if not keys.get("OTX_API"):
        return {"skipped": True}
    sec = ("IPv6" if ":" in ioc else "IPv4") if type_ == "IP" else ("domain" if type_ == "DOMAIN" else ("url" if type_ == "URL" else "file"))
    r = request_json("https://otx.alienvault.com/api/v1/indicators/" + sec + "/" + urllib.parse.quote(ioc, safe="") + "/general",
                     "GET", {"X-OTX-API-KEY": keys["OTX_API"]}, None, 60)
    if not r["ok"]:
        return api_error(r, "OTX")
    d = r["data"] or {}
    plist = g(d, "pulse_info", "pulses", default=[])
    pulses = g(d, "pulse_info", "count", default=0)
    pnames = ", ".join([p.get("name", "") for p in plist[:5]]) or "None"
    tagset = []
    for p in plist:
        for tag in (p.get("tags") or []):
            if tag not in tagset:
                tagset.append(tag)
    return {"pulses": pulses, "pulse_names": pnames, "tags": ", ".join(tagset[:8]) or "None", "status": r["status"]}


def scan_urlscan(domain_or_url):
    if not keys.get("URLSCAN"):
        return {"skipped": True}
    host = host_from_url(domain_or_url) if re.match(r"^https?://", domain_or_url, re.I) else domain_or_url
    r = request_json("https://urlscan.io/api/v1/search/?q=" + urllib.parse.quote("domain:" + host, safe=""),
                     "GET", {"API-Key": keys["URLSCAN"]}, None, 60)
    if not r["ok"]:
        return api_error(r, "urlscan")
    d = r["data"] or {}
    first = (d.get("results") or [None])[0] or {}
    page = first.get("page", {}) if isinstance(first, dict) else {}
    return {"total": d.get("total", 0), "last_scan": g(first, "task", "time", default="N/A"),
            "ip": page.get("ip", "N/A"), "server": page.get("server", "N/A"),
            "asn": page.get("asnname", "N/A"), "title": page.get("title", "N/A"), "status": r["status"]}


def scan_malwarebazaar(hash_):
    if not keys.get("MB_API"):
        return {"skipped": True}
    r = request_json("https://mb-api.abuse.ch/api/v1/", "POST",
                     {"Auth-Key": keys["MB_API"], "Content-Type": "application/x-www-form-urlencoded"},
                     "query=get_info&hash=" + urllib.parse.quote(hash_, safe=""), 60)
    if not r["ok"]:
        return api_error(r, "MalwareBazaar")
    data = r["data"] or {}
    if data.get("query_status") != "ok":
        return {"status": data.get("query_status") or "not_found"}
    d = (data.get("data") or [None])[0]
    if not d:
        return {"status": "not_found"}
    vi = d.get("vendor_intel") or {}
    return {"status": "ok", "file_name": d.get("file_name", "N/A"), "signature": d.get("signature", "N/A"),
            "tags": ",".join(d.get("tags") or []) or "N/A", "first_seen": d.get("first_seen", "N/A"),
            "anyrun": g(vi, "ANY.RUN", 0, "verdict", default="N/A"),
            "kaspersky": g(vi, "Kaspersky", "verdict", default="N/A")}


def scan_cloudflare(url):
    if not keys.get("CF_ACCOUNT_ID") or not keys.get("CF_TOKEN"):
        return {"skipped": True}
    base = "https://api.cloudflare.com/client/v4/accounts/" + urllib.parse.quote(keys["CF_ACCOUNT_ID"], safe="") + "/urlscanner/v2"
    sub = request_json(base + "/scan", "POST",
                       {"Authorization": "Bearer " + keys["CF_TOKEN"], "Content-Type": "application/json"},
                       json.dumps({"url": url, "visibility": "public"}), 60)
    if not sub["ok"]:
        return api_error(sub, "Cloudflare")
    sid = sub["data"].get("uuid") or g(sub, "data", "result", "uuid")
    if not sid:
        return {"error": "Cloudflare no scan ID", "status": sub["status"]}
    for _ in range(20):
        sleep(2.5)
        poll = request_json(base + "/result/" + urllib.parse.quote(sid, safe=""), "GET",
                            {"Authorization": "Bearer " + keys["CF_TOKEN"]}, None, 60)
        if not poll["ok"]:
            continue
        d = poll["data"] or {}
        r = d.get("result") or d
        status = g(r, "task", "status") or d.get("status")
        if status and re.match(r"^(finished|complete|completed)$", str(status), re.I):
            page = r.get("page", {})
            verd = g(r, "verdicts", "overall", default={})
            requests_n = len(g(r, "data", "requests", default=[]))
            ext = ", ".join(g(r, "lists", "linkDomains", default=[])) or "N/A"
            mal = verd.get("malicious")
            return {"malicious": "YES" if mal is True else ("NO" if mal is False else "N/A"),
                    "domain": page.get("domain", "N/A"), "ip": page.get("ip", "N/A"),
                    "country": page.get("country", "N/A"), "asn": page.get("asnname", "N/A"),
                    "requests": requests_n, "external": ext, "scanId": sid, "status": "completed"}
    return {"error": "Cloudflare scan timeout", "status": "timeout"}


def scan_threatyeti(domain):
    if not keys.get("TY_API"):
        return {"skipped": True}
    r = request_json("https://api.alphamountain.ai/intelligence/hostname", "POST", {"Content-Type": "application/json"},
                     json.dumps({"hostname": domain, "license": keys["TY_API"], "version": 1, "sections": ["popularity"]}), 60)
    if not r["ok"]:
        return api_error(r, "ThreatYeti")
    s = g(r, "data", "summary", default={})
    level = "none"
    if s.get("high_risk"):
        level = "high"
    elif s.get("mid_risk"):
        level = "mid"
    elif s.get("low_risk"):
        level = "low"
    return {"risk_level": level, "status": r["status"]}


def gemini_osint(ioc):
    if not keys.get("GEMINI"):
        return "Gemini skipped"
    r = request_json("https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-lite:generateContent?key=" + urllib.parse.quote(keys["GEMINI"], safe=""),
                     "POST", {"Content-Type": "application/json"},
                     json.dumps({"contents": [{"parts": [{"text": 'OSINT for IOC: "' + ioc + '". Threats, malware, C2, abuse. Factual only. If no reliable evidence exists, say so.'}]}],
                                 "tools": [{"google_search": {}}]}), 90)
    if not r["ok"]:
        return "Gemini error: " + str(r.get("error")) + " (" + str(r.get("status")) + ")"
    cands = (r["data"] or {}).get("candidates") or []
    text = g(cands, 0, "content", "parts", 0, "text", default="")
    chunks = g(cands, 0, "groundingMetadata", "groundingChunks", default=[])
    srcs = ", ".join([c["web"]["title"] for c in chunks if isinstance(c, dict) and g(c, "web", "title")])
    return (text + ("\n\nSources: " + srcs if srcs else "")) or "No OSINT found."


def gemini_chat_osint(question):
    if not keys.get("GEMINI") or not current_scan:
        return "Gemini skipped"
    r = request_json("https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-lite:generateContent?key=" + urllib.parse.quote(keys["GEMINI"], safe=""),
                     "POST", {"Content-Type": "application/json"},
                     json.dumps({"contents": [{"parts": [{"text": 'IOC: "' + current_scan["ioc"] + '" Q: ' + question + ". Threat intel, factual."}]}],
                                 "tools": [{"google_search": {}}]}), 90)
    if not r["ok"]:
        return "Gemini error: " + str(r.get("error")) + " (" + str(r.get("status")) + ")"
    cands = (r["data"] or {}).get("candidates") or []
    return g(cands, 0, "content", "parts", 0, "text", default="")


def openai(messages):
    if not keys.get("OPENAI"):
        return "OpenAI skipped"
    temp = config.get("temperature")
    r = request_json("https://api.openai.com/v1/chat/completions", "POST",
                     {"Authorization": "Bearer " + keys["OPENAI"], "Content-Type": "application/json"},
                     json.dumps({"model": config.get("model") or "gpt-4o", "messages": messages,
                                 "temperature": temp if isinstance(temp, (int, float)) else 0.2}), 90)
    if not r["ok"]:
        return "OpenAI error: " + str(r.get("error")) + " (" + str(r.get("status")) + ")"
    return g(r, "data", "choices", 0, "message", "content", default="No response")


# ── scan workflow ────────────────────────────────────────────────────────────
def step_list(t):
    if t == "IP":
        return ["IPInfo", "VirusTotal", "AbuseIPDB", "GreyNoise", "OTX", "Gemini OSINT", "AI Analysis"]
    if t == "DOMAIN":
        return ["VirusTotal", "urlscan.io", "ThreatYeti", "OTX", "Gemini OSINT", "AI Analysis"]
    if t == "URL":
        return ["VirusTotal", "Cloudflare", "urlscan.io", "OTX", "Gemini OSINT", "AI Analysis"]
    if t == "HASH":
        return ["VirusTotal", "MalwareBazaar", "OTX", "Gemini OSINT", "AI Analysis"]
    return ["Scan"]


def build_summary(t, ioc, s, osint):
    lines = ["Type: " + t, "IOC: " + ioc]

    def add(src, fields):
        obj = s.get(src)
        if not obj:
            return
        lines.append("\n" + src + ":")
        if obj.get("disabled"):
            lines.append("status=disabled"); return
        if obj.get("skipped"):
            lines.append("status=skipped"); return
        if obj.get("error"):
            lines.append("error=" + str(obj["error"]))
            if obj.get("status"):
                lines.append("status=" + str(obj["status"]))
            return
        for f in fields:
            if f in obj:
                lines.append(f + "=" + str(obj[f]))

    if t == "IP":
        add("IPInfo", ["country", "as_name"]); add("VirusTotal", ["malicious", "suspicious", "reputation", "asn", "network"])
        add("AbuseIPDB", ["score", "reports", "is_tor", "usage"]); add("GreyNoise", ["noise", "riot", "classification"]); add("OTX", ["pulses", "tags"])
    elif t == "DOMAIN":
        add("VirusTotal", ["malicious", "suspicious", "reputation", "tld", "categories"]); add("urlscan", ["total", "ip", "server"])
        add("ThreatYeti", ["risk_level"]); add("OTX", ["pulses", "tags"])
    elif t == "URL":
        add("VirusTotal", ["malicious", "suspicious"]); add("Cloudflare", ["malicious", "ip", "country", "asn", "requests", "external"])
        add("urlscan", ["total", "ip", "server"]); add("OTX", ["pulses", "tags"])
    elif t == "HASH":
        add("VirusTotal", ["malicious", "suspicious", "family", "filetype"]); add("MalwareBazaar", ["file_name", "signature", "anyrun", "kaspersky"]); add("OTX", ["pulses", "tags"])
    lines.append("\nGoogle OSINT:\n" + (osint or "N/A"))
    return "\n".join(lines)


def run_scan(ioc, emit):
    ioc = refang(str(ioc or "").strip())
    t = detect_type(ioc)
    if t == "UNKNOWN":
        return {"error": "Unknown IOC type"}
    sources = {}
    emit("progress", step_list(t))

    def step(step_name, src_name, fn):
        emit("step", step_name)
        data = {"disabled": True} if (src_name and is_disabled(src_name)) else fn()
        if src_name:
            sources[src_name] = data
            emit("source", {"name": src_name, "data": data})
        return data

    if t == "IP":
        step("IPInfo", "IPInfo", lambda: scan_ipinfo(ioc))
        step("VirusTotal", "VirusTotal", lambda: scan_vt(ioc, t))
        step("AbuseIPDB", "AbuseIPDB", lambda: scan_abuseipdb(ioc))
        step("GreyNoise", "GreyNoise", lambda: scan_greynoise(ioc))
        step("OTX", "OTX", lambda: scan_otx(ioc, t))
    elif t == "DOMAIN":
        step("VirusTotal", "VirusTotal", lambda: scan_vt(ioc, t))
        step("urlscan.io", "urlscan", lambda: scan_urlscan(ioc))
        step("ThreatYeti", "ThreatYeti", lambda: scan_threatyeti(ioc))
        step("OTX", "OTX", lambda: scan_otx(ioc, t))
    elif t == "URL":
        step("VirusTotal", "VirusTotal", lambda: scan_vt(ioc, t))
        step("Cloudflare", "Cloudflare", lambda: scan_cloudflare(ioc))
        step("urlscan.io", "urlscan", lambda: scan_urlscan(ioc))
        step("OTX", "OTX", lambda: scan_otx(ioc, t))
    elif t == "HASH":
        step("VirusTotal", "VirusTotal", lambda: scan_vt(ioc, t))
        step("MalwareBazaar", "MalwareBazaar", lambda: scan_malwarebazaar(ioc))
        step("OTX", "OTX", lambda: scan_otx(ioc, t))

    emit("step", "Gemini OSINT")
    osint = "Gemini OSINT disabled" if is_disabled("Gemini OSINT") else gemini_osint(ioc)
    summary = build_summary(t, ioc, sources, osint)
    emit("step", "AI Analysis")
    ai_result = openai([{"role": "system", "content": sys_prompt(t)},
                        {"role": "user", "content": user_prompt(t, ioc, summary)}])
    return {"type": t, "ioc": ioc, "sources": sources, "osint": osint, "summary": summary,
            "aiResult": ai_result, "verdict": parse_verdict(ai_result)}


def handle_chat(question, siem):
    global current_scan
    if not current_scan:
        return "Run a scan first."
    chat = get_chat(current_scan["ioc"])
    fresh = gemini_chat_osint(question) if keys.get("GEMINI") else "Gemini skipped"
    sysmsg = ("Senior SOC analyst. IOC: " + current_scan["ioc"] + " Type: " + current_scan["type"] +
              " Verdict: " + current_scan["verdict"] + "\nScan data:\n" + current_scan["summary"])
    messages = list(chat["messages"]) if chat["messages"] else [{"role": "system", "content": sysmsg}]
    if siem:
        user_content = ("Generate " + siem + " detection rules for IOC: " + current_scan["ioc"] +
                        ".\nWeb intel: " + (fresh or "None.") + "\nBe syntactically correct.")
    else:
        user_content = "Web intel: " + (fresh or "None.") + "\nQuestion: " + question
    messages = messages + [{"role": "user", "content": user_content}]
    if len(messages) > 21:
        messages = [messages[0]] + messages[-20:]
    answer = openai(messages)
    chat["messages"] = messages + [{"role": "assistant", "content": answer}]
    chat["transcript"].append({"type": "q", "text": ("SIEM: " + siem) if siem else question})
    chat["transcript"].append({"type": "a", "text": answer})
    save_chats()
    return answer


# ── key validation ───────────────────────────────────────────────────────────
def test_key(code):
    v = keys.get(code)
    v = v.strip() if isinstance(v, str) else v
    if not v:
        return "unset"

    def fail(reason):
        return "fail: " + str(reason)

    try:
        if code == "VT_API":
            r = request_json("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8", "GET", {"x-apikey": v}, None, 15)
            return "ok" if r["ok"] else fail("HTTP %s" % r["status"])
        if code == "ABUSEIPDB":
            r = request_json("https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90", "GET", {"Key": v, "Accept": "application/json"}, None, 15)
            return "ok" if r["ok"] else fail("HTTP %s" % r["status"])
        if code == "IPINFO":
            r = request_json("https://api.ipinfo.io/lite/8.8.8.8?token=" + urllib.parse.quote(v, safe=""), "GET", None, None, 15)
            return "ok" if r["ok"] else fail("HTTP %s" % r["status"])
        if code == "GREYNOISE":
            r = request_json("https://api.greynoise.io/v3/community/8.8.8.8", "GET", {"key": v}, None, 15)
            return "ok" if (r["ok"] or r["status"] == 404) else fail("HTTP %s" % r["status"])
        if code == "URLSCAN":
            r = request_json("https://urlscan.io/api/v1/search/?q=domain:example.com", "GET", {"API-Key": v}, None, 15)
            return "ok" if r["ok"] else fail("HTTP %s" % r["status"])
        if code == "OTX_API":
            r = request_json("https://otx.alienvault.com/api/v1/user/me", "GET", {"X-OTX-API-KEY": v}, None, 15)
            return "ok" if r["ok"] else fail("HTTP %s" % r["status"])
        if code in ("CF_TOKEN", "CF_ACCOUNT_ID"):
            if not keys.get("CF_ACCOUNT_ID"):
                return fail("needs Cloudflare Account ID")
            if not keys.get("CF_TOKEN"):
                return fail("needs Cloudflare API Token")
            r = request_json("https://api.cloudflare.com/client/v4/accounts/" + urllib.parse.quote(keys["CF_ACCOUNT_ID"], safe="") + "/urlscanner/v2/search?size=1",
                             "GET", {"Authorization": "Bearer " + keys["CF_TOKEN"]}, None, 15)
            if r["ok"]:
                return "ok"
            return fail("HTTP %s%s" % (r["status"], " (token lacks URL Scanner)" if r["status"] == 403 else ""))
        if code == "TY_API":
            r = request_json("https://api.alphamountain.ai/intelligence/hostname", "POST", {"Content-Type": "application/json"},
                             json.dumps({"hostname": "example.com", "license": v, "version": 1, "sections": ["popularity"]}), 20)
            return "ok" if r["ok"] else fail("HTTP %s" % r["status"])
        if code == "MB_API":
            r = request_json("https://mb-api.abuse.ch/api/v1/", "POST", {"Auth-Key": v, "Content-Type": "application/x-www-form-urlencoded"},
                             "query=get_info&hash=0000000000000000000000000000000000000000000000000000000000000000", 15)
            if not r["ok"]:
                return fail("HTTP %s" % r["status"])
            qs = str(g(r, "data", "query_status", default=""))
            return fail(qs) if re.search(r"unauth|illegal|invalid", qs, re.I) else "ok"
        if code == "OPENAI":
            r = request_json("https://api.openai.com/v1/models", "GET", {"Authorization": "Bearer " + v}, None, 15)
            return "ok" if r["ok"] else fail("HTTP %s" % r["status"])
        if code == "GEMINI":
            r = request_json("https://generativelanguage.googleapis.com/v1beta/models?key=" + urllib.parse.quote(v, safe=""), "GET", None, None, 15)
            return "ok" if r["ok"] else fail("HTTP %s" % r["status"])
        return "unset"
    except Exception as e:
        return fail(str(e))


def test_all_keys():
    codes = list(KEY_NAMES.keys())
    with ThreadPoolExecutor(max_workers=8) as ex:
        res = list(ex.map(test_key, codes))
    return {c: res[i] for i, c in enumerate(codes)}


def key_status():
    return [{"code": c, "name": KEY_NAMES[c], "set": bool(keys.get(c) and str(keys.get(c)).strip())} for c in KEY_NAMES]


def sanitize_config(body):
    if isinstance(body.get("model"), str) and body["model"] in ALLOWED_MODELS:
        config["model"] = body["model"]
    if isinstance(body.get("temperature"), (int, float)) and 0 <= body["temperature"] <= 1:
        config["temperature"] = body["temperature"]
    if isinstance(body.get("autoCsv"), bool):
        config["autoCsv"] = body["autoCsv"]
    if isinstance(body.get("disabledSources"), list):
        config["disabledSources"] = [s for s in body["disabledSources"] if s in TOGGLEABLE_SOURCES]
    save_config()


# ── HTTP server ──────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b""
            return json.loads(raw.decode("utf-8")) if raw else {}
        except Exception:
            return {}

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        p = u.path
        q = urllib.parse.parse_qs(u.query)
        try:
            if p in ("/", "/index.html"):
                with open(UI_PATH, "rb") as f:
                    body = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if p == "/api/keys":
                return self._json(200, {"keys": key_status()})
            if p == "/api/config":
                return self._json(200, {"config": config, "sources": TOGGLEABLE_SOURCES})
            if p == "/api/history":
                return self._json(200, {"history": history})
            if p == "/api/result":
                global current_scan
                ioc = (q.get("ioc") or [""])[0]
                result = results.get(ioc)
                transcript = []
                if result:
                    current_scan = result
                    transcript = (chats.get(ioc) or {}).get("transcript", [])
                return self._json(200, {"result": result, "transcript": transcript})
            if p == "/api/export.csv":
                body = history_to_csv().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/csv; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="ThreatScore_results.csv"')
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if p == "/api/scan":
                return self._sse_scan((q.get("ioc") or [""])[0])
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
        except BrokenPipeError:
            pass
        except Exception as e:
            try:
                self._json(500, {"error": str(e)})
            except Exception:
                pass

    def do_POST(self):
        global keys, history, results, chats, config, current_scan
        u = urllib.parse.urlparse(self.path)
        p = u.path
        try:
            if p == "/api/keys":
                body = self._read_body()
                code = body.get("name")
                if not code or code not in KEY_NAMES:
                    return self._json(400, {"error": "unknown key"})
                val = str(body.get("value") or "").strip()
                with _lock:
                    if val:
                        keys[code] = val
                    else:
                        keys.pop(code, None)
                    secrets.save(keys)
                return self._json(200, {"ok": True, "keys": key_status()})
            if p == "/api/keys/reset":
                with _lock:
                    keys = {}
                    secrets.save(keys)
                return self._json(200, {"ok": True, "keys": key_status()})
            if p == "/api/keys/test":
                return self._json(200, {"results": test_all_keys()})
            if p == "/api/config":
                sanitize_config(self._read_body())
                return self._json(200, {"ok": True, "config": config})
            if p == "/api/history/clear":
                with _lock:
                    history = []
                    results = {}
                    chats = {}
                    save_history(); save_results(); save_chats()
                return self._json(200, {"ok": True})
            if p == "/api/chat":
                body = self._read_body()
                answer = handle_chat(body.get("question") or "", body.get("siem") or "")
                return self._json(200, {"answer": answer})
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
        except BrokenPipeError:
            pass
        except Exception as e:
            try:
                self._json(500, {"error": str(e)})
            except Exception:
                pass

    def _sse_scan(self, ioc):
        global current_scan
        ioc = refang(ioc)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        def emit(event, data):
            self.wfile.write(("event: " + event + "\ndata: " + json.dumps(data) + "\n\n").encode("utf-8"))
            self.wfile.flush()

        try:
            if detect_type(ioc) == "UNKNOWN":
                emit("scanfail", "Unknown IOC type")
                return
            result = run_scan(ioc, emit)
            if result.get("error"):
                emit("scanfail", result["error"])
                return
            with _lock:
                entry = {"ts": datetime.now().strftime("%H:%M"), "at": now_stamp(),
                         "type": result["type"], "ioc": result["ioc"], "verdict": result["verdict"]}
                history.append(entry)
                if len(history) > 100:
                    history.pop(0)
                save_history()
                results[result["ioc"]] = result
                prune_results()
                save_results()
                chats[result["ioc"]] = {"messages": [], "transcript": []}
                prune_chats()
                save_chats()
                if config.get("autoCsv"):
                    append_csv(entry)
                current_scan = result
            emit("done", {"result": result, "history": history})
        except BrokenPipeError:
            pass
        except Exception as e:
            try:
                emit("scanfail", str(e))
            except Exception:
                pass


def main():
    port = int(os.environ.get("PORT") or 8736)
    httpd = None
    for attempt in range(11):
        try:
            httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
            break
        except OSError:
            port += 1
    if not httpd:
        print("Could not start server."); sys.exit(1)
    url = "http://localhost:%d" % port
    print("ThreatScore (Python) is running at " + url)
    print("Key store: " + secrets.FILE)
    print("Press Ctrl+C to stop.")
    if not os.environ.get("TS_NO_OPEN") and (getattr(sys, "frozen", False) or (sys.stdout and sys.stdout.isatty())):
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
