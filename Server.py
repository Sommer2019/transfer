"""
Stream Deck MK.2 Server — reine Python-Stdlib, kein pip, keine Adminrechte.

Start:   python server.py
UI:      http://127.0.0.1:8710

Voraussetzung: Elgato-Software darf NICHT laufen (haelt das Geraet exklusiv).
"""

import base64
import ctypes
import ctypes.wintypes as wt
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------------------------------------------------------- Konstanten

VID, PID = 0x0FD9, 0x0080          # Stream Deck MK.2
KEY_COUNT = 15
IMG_SIZE = 72                      # 72x72 JPEG, um 180 Grad gedreht
PORT = 8710
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

# 72x72 komplett schwarzes JPEG (zum Leeren einer Taste)
BLACK_JPEG = base64.b64decode(
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAMCAgMCAgMDAwMEAwMEBQgFBQQEBQoHBwYIDAoMDAsKCwsNDhIQDQ4RDgsLEBYQERMUFRUVDA8XGBYUGBIUFRT/2wBDAQMEBAUEBQkFBQkUDQsNFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBT/wAARCABIAEgDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD8qqKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKAP/2Q=="
)

# ---------------------------------------------------------------- Win32 / HID via ctypes

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
hid = ctypes.WinDLL("hid")
setupapi = ctypes.WinDLL("setupapi", use_last_error=True)

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x1
FILE_SHARE_WRITE = 0x2
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
DIGCF_PRESENT = 0x2
DIGCF_DEVICEINTERFACE = 0x10


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wt.DWORD), ("Data2", wt.WORD),
                ("Data3", wt.WORD), ("Data4", ctypes.c_ubyte * 8)]


class SP_DEVICE_INTERFACE_DATA(ctypes.Structure):
    _fields_ = [("cbSize", wt.DWORD), ("InterfaceClassGuid", GUID),
                ("Flags", wt.DWORD), ("Reserved", ctypes.c_void_p)]


class HIDP_CAPS(ctypes.Structure):
    _fields_ = [("Usage", wt.USHORT), ("UsagePage", wt.USHORT),
                ("InputReportByteLength", wt.USHORT),
                ("OutputReportByteLength", wt.USHORT),
                ("FeatureReportByteLength", wt.USHORT),
                ("Reserved", wt.USHORT * 17),
                ("Rest", wt.USHORT * 10)]


def _enumerate_hid_paths():
    """Liefert alle HID-Device-Pfade des Systems."""
    guid = GUID()
    hid.HidD_GetHidGuid(ctypes.byref(guid))
    devinfo = setupapi.SetupDiGetClassDevsW(
        ctypes.byref(guid), None, None, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE)
    if devinfo == INVALID_HANDLE_VALUE:
        return
    try:
        idx = 0
        while True:
            ifd = SP_DEVICE_INTERFACE_DATA()
            ifd.cbSize = ctypes.sizeof(SP_DEVICE_INTERFACE_DATA)
            if not setupapi.SetupDiEnumDeviceInterfaces(
                    devinfo, None, ctypes.byref(guid), idx, ctypes.byref(ifd)):
                break
            idx += 1
            # Groesse des Detail-Buffers erfragen
            needed = wt.DWORD(0)
            setupapi.SetupDiGetDeviceInterfaceDetailW(
                devinfo, ctypes.byref(ifd), None, 0, ctypes.byref(needed), None)
            buf = ctypes.create_string_buffer(needed.value)
            # cbSize der Detail-Struktur: 8 auf x64, 6 auf x86
            cb = 6 if ctypes.sizeof(ctypes.c_void_p) == 4 else 8
            ctypes.memmove(buf, ctypes.byref(wt.DWORD(cb)), 4)
            if setupapi.SetupDiGetDeviceInterfaceDetailW(
                    devinfo, ctypes.byref(ifd), buf, needed, None, None):
                path = ctypes.wstring_at(ctypes.addressof(buf) + 4)
                yield path
    finally:
        setupapi.SetupDiDestroyDeviceInfoList(devinfo)


class StreamDeck:
    """Minimaler Treiber fuer Stream Deck MK.2 (Gen2-Protokoll)."""

    def __init__(self):
        self.handle = None
        self.out_len = 1024
        self.in_len = 512
        self.feat_len = 32
        self.lock = threading.Lock()   # serialisiert Schreibzugriffe

    # ---- Verbindung

    def open(self):
        needle = f"vid_{VID:04x}&pid_{PID:04x}"
        for path in _enumerate_hid_paths():
            if needle not in path.lower():
                continue
            h = kernel32.CreateFileW(
                path, GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None, OPEN_EXISTING, 0, None)
            if h == INVALID_HANDLE_VALUE:
                continue  # vermutlich von Elgato-Software blockiert
            # Report-Laengen auslesen
            pre = ctypes.c_void_p()
            if hid.HidD_GetPreparsedData(h, ctypes.byref(pre)):
                caps = HIDP_CAPS()
                hid.HidP_GetCaps(pre, ctypes.byref(caps))
                hid.HidD_FreePreparsedData(pre)
                self.in_len = caps.InputReportByteLength or 512
                self.out_len = caps.OutputReportByteLength or 1024
                self.feat_len = caps.FeatureReportByteLength or 32
            self.handle = h
            return True
        return False

    def close(self):
        if self.handle:
            kernel32.CloseHandle(self.handle)
            self.handle = None

    @property
    def connected(self):
        return self.handle is not None

    # ---- Low-Level I/O

    def _write(self, data: bytes):
        buf = ctypes.create_string_buffer(data.ljust(self.out_len, b"\x00"),
                                          self.out_len)
        written = wt.DWORD(0)
        with self.lock:
            ok = kernel32.WriteFile(self.handle, buf, self.out_len,
                                    ctypes.byref(written), None)
        if not ok:
            raise OSError("WriteFile fehlgeschlagen")

    def _set_feature(self, data: bytes):
        buf = ctypes.create_string_buffer(data.ljust(self.feat_len, b"\x00"),
                                          self.feat_len)
        if not hid.HidD_SetFeature(self.handle, buf, self.feat_len):
            raise OSError("HidD_SetFeature fehlgeschlagen")

    def read_report(self):
        """Blockierend; liefert rohen Input-Report oder None bei Fehler."""
        buf = ctypes.create_string_buffer(self.in_len)
        n = wt.DWORD(0)
        if not kernel32.ReadFile(self.handle, buf, self.in_len,
                                 ctypes.byref(n), None):
            return None
        return buf.raw[: n.value]

    # ---- Stream-Deck-Protokoll

    def set_brightness(self, percent: int):
        self._set_feature(bytes([0x03, 0x08, max(0, min(100, percent))]))

    def reset(self):
        self._set_feature(bytes([0x03, 0x02]))

    def set_key_image(self, key: int, jpeg: bytes):
        """jpeg: fertiges 72x72-JPEG, bereits um 180 Grad gedreht."""
        payload_max = self.out_len - 8
        page = 0
        remaining = jpeg
        while remaining or page == 0:
            chunk, remaining = remaining[:payload_max], remaining[payload_max:]
            header = bytes([
                0x02, 0x07, key, 0 if remaining else 1,
                len(chunk) & 0xFF, len(chunk) >> 8,
                page & 0xFF, page >> 8,
            ])
            self._write(header + chunk)
            page += 1

    def clear_key(self, key: int):
        self.set_key_image(key, BLACK_JPEG)

    def parse_keys(self, report: bytes):
        """Gen2: Report-ID 0x01, Tastenzustaende ab Byte 4."""
        if not report or report[0] != 0x01:
            return None
        return list(report[4: 4 + KEY_COUNT])


# ---------------------------------------------------------------- Konfiguration

config_lock = threading.Lock()


def load_config():
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {"brightness": 60, "keys": {}}


def save_config(cfg):
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=1)
    os.replace(tmp, CONFIG_PATH)


config = load_config()

# ---------------------------------------------------------------- Deck-Logik

deck = StreamDeck()
key_states = [0] * KEY_COUNT


def apply_full_config():
    """Nach (Re-)Connect: Helligkeit und alle Tastenbilder pushen."""
    deck.set_brightness(config.get("brightness", 60))
    for i in range(KEY_COUNT):
        entry = config["keys"].get(str(i))
        if entry and entry.get("jpeg"):
            deck.set_key_image(i, base64.b64decode(entry["jpeg"]))
        else:
            deck.clear_key(i)


def run_command(cmd: str):
    print(f"[cmd] {cmd}")
    try:
        subprocess.Popen(cmd, shell=True)
    except OSError as e:
        print(f"[cmd] Fehler: {e}")


def deck_thread():
    global key_states
    while True:
        if not deck.connected:
            if deck.open():
                print("[deck] verbunden")
                try:
                    apply_full_config()
                except OSError:
                    deck.close()
                    continue
            else:
                time.sleep(2)
                continue
        report = deck.read_report()
        if report is None:
            print("[deck] Verbindung verloren")
            deck.close()
            key_states = [0] * KEY_COUNT
            continue
        states = deck.parse_keys(report)
        if states is None:
            continue
        for i, (old, new) in enumerate(zip(key_states, states)):
            if new and not old:  # Flanke: gedrueckt
                entry = config["keys"].get(str(i))
                if entry and entry.get("command"):
                    run_command(entry["command"])
        key_states = states


# ---------------------------------------------------------------- HTTP-Server

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # Konsole ruhig halten
        pass

    def _json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length) or b"{}")

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            try:
                with open(os.path.join(BASE_DIR, "index.html"), "rb") as f:
                    body = f.read()
            except OSError:
                self.send_error(404, "index.html fehlt")
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/config":
            with config_lock:
                self._json(config)
        elif self.path == "/api/status":
            self._json({"connected": deck.connected, "keys": key_states})
        else:
            self.send_error(404)

    def do_POST(self):
        try:
            data = self._read_body()
        except (ValueError, json.JSONDecodeError):
            self._json({"error": "ungueltiges JSON"}, 400)
            return

        if self.path == "/api/key":
            key = int(data.get("key", -1))
            if not 0 <= key < KEY_COUNT:
                self._json({"error": "key ausserhalb 0-14"}, 400)
                return
            with config_lock:
                entry = config["keys"].setdefault(str(key), {})
                if "label" in data:
                    entry["label"] = data["label"]
                if "command" in data:
                    entry["command"] = data["command"]
                if "jpeg" in data:          # null/"" = Taste leeren
                    entry["jpeg"] = data["jpeg"] or ""
                save_config(config)
            if deck.connected and "jpeg" in data:
                try:
                    if data["jpeg"]:
                        deck.set_key_image(key, base64.b64decode(data["jpeg"]))
                    else:
                        deck.clear_key(key)
                except OSError:
                    deck.close()
            self._json({"ok": True})

        elif self.path == "/api/brightness":
            val = max(0, min(100, int(data.get("value", 60))))
            with config_lock:
                config["brightness"] = val
                save_config(config)
            if deck.connected:
                try:
                    deck.set_brightness(val)
                except OSError:
                    deck.close()
            self._json({"ok": True})

        else:
            self.send_error(404)


# ---------------------------------------------------------------- main

def main():
    if sys.platform != "win32":
        print("Nur fuer Windows (hid.dll/setupapi.dll).")
        sys.exit(1)
    threading.Thread(target=deck_thread, daemon=True).start()
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"UI: http://127.0.0.1:{PORT}")
    print("Hinweis: Elgato-Software muss beendet sein.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
