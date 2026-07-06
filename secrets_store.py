"""API-key storage for ThreatScore (Python).

Keys are kept in a single JSON blob encrypted with Windows DPAPI (CurrentUser
scope) via ctypes -> crypt32. This is byte-compatible with the Node version's
PowerShell ProtectedData approach, so both editions share %APPDATA%\\ThreatScore\\keys.dat.
"""

import os
import json
import base64
import ctypes
from ctypes import wintypes

DIR = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "ThreatScore")
FILE = os.path.join(DIR, "keys.dat")


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob_to_bytes(blob):
    size = int(blob.cbData)
    buf = ctypes.create_string_buffer(size)
    ctypes.memmove(buf, blob.pbData, size)
    ctypes.windll.kernel32.LocalFree(blob.pbData)
    return buf.raw


def _protect(plain: bytes) -> bytes:
    src = DATA_BLOB(len(plain), ctypes.cast(ctypes.c_char_p(plain), ctypes.POINTER(ctypes.c_char)))
    out = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptProtectData(ctypes.byref(src), None, None, None, None, 0, ctypes.byref(out)):
        raise ctypes.WinError()
    return _blob_to_bytes(out)


def _unprotect(enc: bytes) -> bytes:
    src = DATA_BLOB(len(enc), ctypes.cast(ctypes.c_char_p(enc), ctypes.POINTER(ctypes.c_char)))
    out = DATA_BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(src), None, None, None, None, 0, ctypes.byref(out)):
        raise ctypes.WinError()
    return _blob_to_bytes(out)


def load() -> dict:
    try:
        if not os.path.exists(FILE):
            return {}
        with open(FILE, "r", encoding="utf-8") as f:
            enc = f.read().strip()
        if not enc:
            return {}
        data = _unprotect(base64.b64decode(enc))
        return json.loads(data.decode("utf-8")) or {}
    except Exception as e:
        print("Could not read key store (starting empty):", e)
        return {}


def save(keys: dict) -> bool:
    try:
        os.makedirs(DIR, exist_ok=True)
        enc = base64.b64encode(_protect(json.dumps(keys or {}).encode("utf-8")))
        with open(FILE, "w", encoding="utf-8") as f:
            f.write(enc.decode("ascii"))
        return True
    except Exception as e:
        print("Could not save key store:", e)
        return False
