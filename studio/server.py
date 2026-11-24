"""
Haylou Watch 4S Studio — local Studio backend.

Serves the browser designer, compiles .bin files, manages presets, and bridges
ADB for pushing dials / installing the modded companion app.

Runs on 127.0.0.1 only. No network exposure, no telemetry, no accounts.
"""

import base64
import glob
import io
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import uuid
import webbrowser
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STUDIO_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.abspath(os.path.join(STUDIO_DIR, ".."))
SCRIPTS_DIR = os.path.join(PROJECT_DIR, "scripts")
PRESETS_DIR = os.path.join(PROJECT_DIR, "presets")
FONTS_DIR = os.path.join(PROJECT_DIR, "fonts")
MODDED_APK = os.path.join(PROJECT_DIR, "haylou-fun-v4-0-8-noclock.apk")

HOST = "127.0.0.1"
PORT = int(os.environ.get("STUDIO_PORT", "8466"))

MAX_JSON_BODY = 32 * 1024 * 1024
MAX_BIN_BYTES = 8 * 1024 * 1024
MAX_FONT_BYTES = 8 * 1024 * 1024
MAX_IMAGE_BYTES = 16 * 1024 * 1024
FONT_MAGICS = (b"\x00\x01\x00\x00", b"true", b"OTTO", b"ttcf", b"wOFF", b"wOF2")
KNOWN_BIN_FLAGS = (0x0002, 0x0012, 0x0023)
BUNDLE_FILES = ("meta.json", "config.json", "preview.png", "source.png", "watchface.bin")

sys.path.insert(0, SCRIPTS_DIR)
from watchface_bin_maker import push_bin_to_phone
from watchface_compiler import (
    compile_config_to_bin,
    decode_bin_preview,
    render_config_preview,
)

os.makedirs(PRESETS_DIR, exist_ok=True)
os.makedirs(FONTS_DIR, exist_ok=True)

_adb_cache = {"at": 0.0, "value": None}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def slugify(name):
    s = re.sub(r"[^a-zA-Z0-9_-]+", "_", name.strip()).strip("_").lower()
    return s or f"preset_{int(time.time())}"


def safe_preset_dir(pid):
    """Return a canonical preset directory, or None if the id escapes presets/."""
    if not isinstance(pid, str) or not pid or pid in (".", ".."):
        return None
    if os.path.isabs(pid) or "/" in pid or "\\" in pid or ".." in pid:
        return None
    base = os.path.realpath(PRESETS_DIR)
    path = os.path.realpath(os.path.join(base, pid))
    if path == base or os.path.commonpath([base, path]) != base:
        return None
    return path


def valid_bin(raw):
    if not (16 <= len(raw) <= MAX_BIN_BYTES):
        return False
    flags, magic = struct.unpack_from("<HH", raw, 0)
    return flags in KNOWN_BIN_FLAGS and magic == 0xFFFF


def origin_allowed(headers):
    origin = headers.get("Origin")
    if not origin:
        return True
    return origin.rstrip("/") in (f"http://{HOST}:{PORT}", f"http://localhost:{PORT}")


def host_allowed(headers):
    host = (headers.get("Host") or "").split(":")[0].strip()
    return host in (HOST, "localhost")


def check_adb():
    """Cached, read-only ADB status with installed-app detection."""
    now = time.time()
    if _adb_cache["value"] is not None and now - _adb_cache["at"] < 8:
        return _adb_cache["value"]

    result = {"connected": False, "detail": "No phone connected via USB"}
    try:
        res = subprocess.run(["adb", "devices", "-l"], capture_output=True, text=True, timeout=4)
        if res.returncode != 0:
            result = {"connected": False, "detail": "ADB not found or failed to start"}
        else:
            for line in res.stdout.splitlines()[1:]:
                parts = line.strip().split()
                if len(parts) < 2:
                    continue
                if parts[1] == "unauthorized":
                    result = {"connected": False, "detail": "Phone unauthorized — tap Allow on phone"}
                    break
                if parts[1] != "device":
                    continue
                serial = parts[0]
                model = ""
                for p in parts[2:]:
                    if p.startswith("model:"):
                        model = p.split(":", 1)[1]
                installed = False
                try:
                    pr = subprocess.run(
                        ["adb", "-s", serial, "shell", "pm", "path", "com.yingsheng.hayloufun"],
                        capture_output=True, text=True, timeout=4,
                    )
                    installed = pr.returncode == 0 and "base.apk" in pr.stdout
                except Exception:
                    pass
                result = {
                    "connected": True,
                    "serial": serial,
                    "model": model or serial,
                    "app_installed": installed,
                }
                break
    except Exception as exc:
        result = {"connected": False, "detail": str(exc)}

    _adb_cache["at"] = now
    _adb_cache["value"] = result
    return result


WINDOWS_FONTS = (
    ("Arial Bold", "arialbd.ttf"),
    ("Impact", "impact.ttf"),
    ("Segoe UI Bold", "segoeuib.ttf"),
    ("Bahnschrift", "bahnschrift.ttf"),
    ("Consolas Bold", "consolab.ttf"),
    ("Calibri Bold", "calibrib.ttf"),
    ("Georgia Bold", "georgiab.ttf"),
    ("Verdana Bold", "verdanab.ttf"),
    ("Trebuchet MS Bold", "trebucbd.ttf"),
    ("Courier New Bold", "courbd.ttf"),
)


def get_all_fonts():
    """User fonts first, then platform system fonts. Works on Win/macOS/Linux."""
    found = []
    seen = set()

    def add(path, label):
        key = os.path.realpath(path)
        if key in seen or not os.path.isfile(path):
            return
        seen.add(key)
        found.append({"label": label, "path": path})

    for fname in sorted(os.listdir(FONTS_DIR)):
        if fname.lower().endswith((".ttf", ".otf", ".ttc")):
            add(os.path.join(FONTS_DIR, fname), os.path.splitext(fname)[0] + " (Custom)")

    if os.name == "nt":
        for label, fname in WINDOWS_FONTS:
            add(os.path.join(r"C:\Windows\Fonts", fname), label + " (System)")
    elif sys.platform == "darwin":
        roots = ("/System/Library/Fonts", "/Library/Fonts", os.path.expanduser("~/Library/Fonts"))
        for root in roots:
            for pattern in ("*.ttf", "*.otf", "*.ttc"):
                for path in sorted(glob.glob(os.path.join(root, pattern)))[:80]:
                    add(path, os.path.splitext(os.path.basename(path))[0] + " (System)")
    else:
        roots = (
            "/usr/share/fonts", "/usr/local/share/fonts",
            os.path.expanduser("~/.fonts"), os.path.expanduser("~/.local/share/fonts"),
        )
        for root in roots:
            if not os.path.isdir(root):
                continue
            for pattern in ("**/*.ttf", "**/*.otf", "**/*.ttc"):
                for path in sorted(glob.glob(os.path.join(root, pattern), recursive=True))[:80]:
                    add(path, os.path.splitext(os.path.basename(path))[0] + " (System)")

    return found[:220]


def list_presets():
    items = []
    for pid in sorted(os.listdir(PRESETS_DIR)):
        pdir = safe_preset_dir(pid)
        if not pdir:
            continue
        meta_path = os.path.join(pdir, "meta.json")
        bin_path = os.path.join(pdir, "watchface.bin")
        if not (os.path.isdir(pdir) and os.path.exists(meta_path) and os.path.exists(bin_path)):
            continue
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            meta["id"] = pid
            meta["size_kb"] = round(os.path.getsize(bin_path) / 1024.0, 1)
            meta["editable"] = os.path.exists(os.path.join(pdir, "config.json"))
            meta["preview_url"] = f"/presets/{urllib.parse.quote(pid)}/preview.png?t={int(os.path.getmtime(bin_path))}"
            items.append(meta)
        except Exception:
            continue
    items.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    return items


def summarize_config(cfg):
    parts = []
    bg = cfg.get("background", {})
    mode = bg.get("mode")
    if mode == "omnitrix":
        parts.append(f"Omnitrix ({bg.get('omni_style', 'alien_force').upper()})")
    elif mode == "pipboy":
        parts.append("Pip-Boy 3000 (CRT Terminal)")
    elif mode == "image":
        parts.append("Custom Image")
    else:
        parts.append("Gradient/Solid")
    if cfg.get("digital_clock", {}).get("enabled"):
        parts.append(f"Digital ({cfg['digital_clock'].get('layout', 'horizontal')})")
    if cfg.get("analog_hands", {}).get("enabled"):
        parts.append(f"Hands ({cfg['analog_hands'].get('style', 'omnitrix')})")
    if cfg.get("battery", {}).get("enabled"):
        parts.append(f"Battery ({cfg['battery'].get('style', 'ring')})")
    if cfg.get("weekday", {}).get("enabled"):
        parts.append("Weekday")
    if cfg.get("telemetry", {}).get("enabled"):
        parts.append("Live Telemetry (Steps, BPM, Cal)")
    if len(parts) == 1:
        parts.append("Pure Image · No Clock")
    return " · ".join(parts)


def resolve_config_image(cfg, temp_dir=None, filename=None):
    """Write inline base64 image data to a unique/requested file and point config at it."""
    cfg_copy = json.loads(json.dumps(cfg))
    bg = cfg_copy.get("background", {})
    img_b64 = bg.pop("image_data", None)
    if bg.get("mode") == "image" and img_b64:
        if "," in img_b64:
            img_b64 = img_b64.split(",", 1)[1]
        raw = base64.b64decode(img_b64)
        if len(raw) > MAX_IMAGE_BYTES:
            raise ValueError("Image too large (limit 16 MB).")
        out_dir = temp_dir or tempfile.gettempdir()
        os.makedirs(out_dir, exist_ok=True)
        name = filename or f"studio_source_{uuid.uuid4().hex}.png"
        img_path = os.path.join(out_dir, name)
        with open(img_path, "wb") as f:
            f.write(raw)
        bg["image_path"] = img_path
    return cfg_copy


def default_config_for(pid, meta):
    """Auto-migrate an imported legacy preset that has no config.json."""
    if meta.get("type") == "omnitrix" or "omnitrix" in pid.lower():
        return {
            "background": {"mode": "omnitrix", "omni_style": "alien_force", "omni_hex": "#39ff14",
                           "omni_glow": 1.0, "omni_ticks": True, "brightness": 100, "vignette": 0},
            "digital_clock": {"enabled": False},
            "analog_hands": {"enabled": True, "style": "omnitrix", "color": "#39ff14",
                             "accent_color": "#ebffe6", "show_seconds": True, "center_cap": False},
            "battery": {"enabled": True, "style": "ring", "color": "#39ff14", "thickness": 6},
            "weekday": {"enabled": False},
        }
    src_img = os.path.join(PRESETS_DIR, pid, "source.png")
    prev_img = os.path.join(PRESETS_DIR, pid, "preview.png")
    if not os.path.exists(src_img) and os.path.exists(prev_img):
        shutil.copy2(prev_img, src_img)
    return {
        "background": {"mode": "image", "image_path": src_img, "brightness": 100, "vignette": 0},
        "digital_clock": {"enabled": False},
        "analog_hands": {"enabled": False},
        "battery": {"enabled": False},
        "weekday": {"enabled": False},
    }


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #

class StudioHandler(BaseHTTPRequestHandler):
    server_version = "Studio/1.0"

    def log_message(self, fmt, *args):
        if os.environ.get("STUDIO_LOG"):
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def send_json(self, obj, status=200):
        raw = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(raw)

    def send_bytes(self, raw, content_type, filename=None):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(raw)

    def send_file(self, path, content_type):
        if not os.path.isfile(path):
            self.send_json({"ok": False, "error": "Not found."}, 404)
            return
        with open(path, "rb") as f:
            self.send_bytes(f.read(), content_type)

    def read_json_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > MAX_JSON_BODY:
            raise ValueError("Request too large (limit 32 MB).")
        raw = self.rfile.read(length) if length > 0 else b"{}"
        return json.loads(raw.decode("utf-8"))

    def guard(self):
        if not host_allowed(self.headers) or not origin_allowed(self.headers):
            self.send_json({"ok": False, "error": "Forbidden — open the Studio at 127.0.0.1 only."}, 403)
            return False
        return True

    def do_OPTIONS(self):
        self.guard()

    def do_GET(self):
        if not self.guard():
            return
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            self.send_file(os.path.join(STUDIO_DIR, "index.html"), "text/html; charset=utf-8")
        elif path == "/api/adb-status":
            self.send_json(check_adb())
        elif path == "/api/fonts":
            self.send_json({"fonts": get_all_fonts()})
        elif path == "/api/presets":
            self.send_json({"presets": list_presets()})
        elif path == "/api/preset-config":
            qs = urllib.parse.parse_qs(parsed.query)
            pid = qs.get("id", [""])[0]
            pdir = safe_preset_dir(pid)
            if not pdir or not os.path.isdir(pdir):
                self.send_json({"ok": False, "error": "Preset not found."}, 404)
                return
            meta_path = os.path.join(pdir, "meta.json")
            meta = {}
            if os.path.exists(meta_path):
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        meta = json.load(f)
                except Exception:
                    pass
            cfg_path = os.path.join(pdir, "config.json")
            cfg = {}
            if os.path.exists(cfg_path):
                try:
                    with open(cfg_path, "r", encoding="utf-8") as f:
                        cfg = json.load(f)
                except Exception:
                    cfg = {}
            if isinstance(cfg.get("config"), dict):
                inner = cfg.pop("config")
                for k, v in inner.items():
                    cfg.setdefault(k, v)
            src_img = os.path.join(pdir, "source.png")
            if os.path.exists(src_img):
                with open(src_img, "rb") as f:
                    cfg.setdefault("background", {})["image_data"] = "data:image/png;base64," + base64.b64encode(f.read()).decode("ascii")
            self.send_json({"ok": True, "id": pid, "name": meta.get("name", pid), "config": cfg})
        elif path == "/api/preset-bundle":
            qs = urllib.parse.parse_qs(parsed.query)
            pid = qs.get("id", [""])[0]
            pdir = safe_preset_dir(pid)
            if not pdir or not os.path.exists(os.path.join(pdir, "watchface.bin")):
                self.send_json({"ok": False, "error": "Preset not found."}, 404)
                return
            buf = io.BytesIO()
            try:
                with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                    for fname in BUNDLE_FILES:
                        fpath = os.path.join(pdir, fname)
                        if os.path.isfile(fpath):
                            zf.write(fpath, arcname=fname)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, 500)
                return
            self.send_bytes(buf.getvalue(), "application/zip", f"{slugify(pid)}.face.zip")
        elif path.startswith("/presets/"):
            rel = path[len("/presets/"):].strip("/")
            parts = rel.split("/")
            if len(parts) == 2 and parts[1] == "preview.png":
                pdir = safe_preset_dir(parts[0])
                if pdir:
                    self.send_file(os.path.join(pdir, "preview.png"), "image/png")
                    return
            self.send_json({"ok": False, "error": "Not found."}, 404)
        else:
            self.send_json({"ok": False, "error": "Not found."}, 404)

    def do_POST(self):
        if not self.guard():
            return
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        try:
            body = self.read_json_body()
        except Exception as exc:
            self.send_json({"ok": False, "error": f"Invalid request: {exc}"}, 400)
            return

        if path == "/api/render-preview":
            try:
                cfg = body.get("config", {})
                with tempfile.TemporaryDirectory(prefix="studio_preview_") as td:
                    resolved = resolve_config_image(cfg, temp_dir=td)
                    img = render_config_preview(resolved)
                buf = io.BytesIO()
                img.save(buf, format="PNG")
                self.send_bytes(buf.getvalue(), "image/png")
            except Exception as exc:
                self.send_json({"ok": False, "error": f"Preview failed: {exc}"}, 500)

        elif path == "/api/save-preset":
            try:
                name = (body.get("name") or "").strip()[:80] or "Custom Watchface"
                edit_id = (body.get("edit_id") or "").strip()
                cfg = body.get("config", {})
                auto_push = bool(body.get("push", False))

                pdir = safe_preset_dir(edit_id) if edit_id else None
                if edit_id and not pdir:
                    self.send_json({"ok": False, "error": "Invalid preset id."}, 400)
                    return
                if not pdir:
                    pid = slugify(name)
                    pdir = safe_preset_dir(pid)
                    if not pdir:
                        self.send_json({"ok": False, "error": "Could not derive a preset id."}, 400)
                        return
                    if os.path.exists(pdir):
                        pdir = os.path.join(PRESETS_DIR, f"{pid}_{int(time.time()) % 10000}")
                    os.makedirs(pdir, exist_ok=True)
                else:
                    pid = edit_id

                resolved = resolve_config_image(cfg, temp_dir=pdir, filename="source.png")
                if resolved.get("background", {}).get("mode") == "image" and not resolved["background"].get("image_path"):
                    existing_src = os.path.join(pdir, "source.png")
                    if os.path.exists(existing_src):
                        resolved["background"]["image_path"] = existing_src

                bin_path = os.path.join(pdir, "watchface.bin")
                prev_path = os.path.join(pdir, "preview.png")
                compile_config_to_bin(resolved, bin_path, save_preview_path=prev_path)
                if not valid_bin(open(bin_path, "rb").read()):
                    self.send_json({"ok": False, "error": "Compiler produced an invalid .bin — not saved."}, 500)
                    return

                with open(os.path.join(pdir, "config.json"), "w", encoding="utf-8") as f:
                    json.dump(resolved, f, indent=2)
                with open(os.path.join(pdir, "meta.json"), "w", encoding="utf-8") as f:
                    json.dump({"name": name, "subtitle": summarize_config(resolved),
                               "created_at": int(time.time())}, f, indent=2)

                pushed = False
                message = f"Saved '{name}' to Presets."
                if auto_push:
                    if not check_adb()["connected"]:
                        message = f"Saved '{name}', but no phone is connected — push skipped."
                    else:
                        subprocess.run(["adb", "shell", "mkdir", "-p",
                                        "/sdcard/Android/data/com.yingsheng.hayloufun/cache"],
                                       capture_output=True)
                        pushed = push_bin_to_phone(bin_path)
                        message = (f"Saved & pushed '{name}'! Open Haylou Fun → Dial Center → install any free cloud dial."
                                   if pushed else f"Saved '{name}', but the push failed — check the USB connection.")
                self.send_json({"ok": True, "id": os.path.basename(pdir), "pushed": pushed, "message": message})
            except Exception as exc:
                self.send_json({"ok": False, "error": f"Could not save: {exc}"}, 500)

        elif path == "/api/prepare-preset":
            pid = body.get("id", "")
            pdir = safe_preset_dir(pid)
            if not pdir or not os.path.isdir(pdir):
                self.send_json({"ok": False, "error": "Preset not found."}, 404)
                return
            cfg_path = os.path.join(pdir, "config.json")
            if not os.path.exists(cfg_path):
                meta_path = os.path.join(pdir, "meta.json")
                meta = {}
                if os.path.exists(meta_path):
                    try:
                        with open(meta_path, "r", encoding="utf-8") as f:
                            meta = json.load(f)
                    except Exception:
                        pass
                cfg = default_config_for(pid, meta)
                with open(cfg_path, "w", encoding="utf-8") as f:
                    json.dump(cfg, f, indent=2)
            self.send_json({"ok": True})

        elif path == "/api/duplicate-preset":
            pid = body.get("id", "")
            src_dir = safe_preset_dir(pid)
            if not src_dir or not os.path.isdir(src_dir):
                self.send_json({"ok": False, "error": "Preset not found."}, 404)
                return
            new_id = f"{pid}_copy_{int(time.time()) % 10000}"
            dst_dir = os.path.join(PRESETS_DIR, new_id)
            try:
                shutil.copytree(src_dir, dst_dir)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, 500)
                return
            meta_path = os.path.join(dst_dir, "meta.json")
            if os.path.exists(meta_path):
                with open(meta_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                meta["name"] = meta.get("name", pid) + " (Copy)"
                meta["created_at"] = int(time.time())
                with open(meta_path, "w", encoding="utf-8") as f:
                    json.dump(meta, f, indent=2)
            self.send_json({"ok": True, "id": new_id, "message": "Preset duplicated."})

        elif path == "/api/delete-preset":
            pid = body.get("id", "")
            pdir = safe_preset_dir(pid)
            if not pdir or not os.path.isdir(pdir):
                self.send_json({"ok": False, "error": "Preset not found."}, 404)
                return
            shutil.rmtree(pdir, ignore_errors=True)
            self.send_json({"ok": True})

        elif path == "/api/import-bin":
            try:
                name = (body.get("name") or "").strip()[:80] or "Imported Watchface"
                b64 = body.get("bin_data", "")
                if "," in b64:
                    b64 = b64.split(",", 1)[1]
                raw = base64.b64decode(b64)
                if not valid_bin(raw):
                    self.send_json({"ok": False, "error": "Not a valid Watch 4S .bin (bad header or too large)."}, 400)
                    return
                pid = slugify(name)
                pdir = safe_preset_dir(pid)
                if not pdir:
                    self.send_json({"ok": False, "error": "Invalid name."}, 400)
                    return
                if os.path.exists(pdir):
                    pdir = os.path.join(PRESETS_DIR, f"{pid}_{int(time.time()) % 10000}")
                os.makedirs(pdir, exist_ok=True)
                with open(os.path.join(pdir, "watchface.bin"), "wb") as f:
                    f.write(raw)
                try:
                    decode_bin_preview(os.path.join(pdir, "watchface.bin")).save(os.path.join(pdir, "preview.png"))
                except Exception:
                    self.send_json({"ok": False, "error": "Header looks valid but the preview could not be decoded."}, 400)
                    return
                with open(os.path.join(pdir, "meta.json"), "w", encoding="utf-8") as f:
                    json.dump({"name": name, "subtitle": "Imported Watch 4S .bin",
                               "created_at": int(time.time())}, f, indent=2)
                self.send_json({"ok": True, "id": os.path.basename(pdir),
                                "message": f"Imported '{name}' into Presets."})
            except Exception as exc:
                self.send_json({"ok": False, "error": f"Import failed: {exc}"}, 400)

        elif path == "/api/import-bundle":
            try:
                b64 = body.get("bundle_data", "")
                if "," in b64:
                    b64 = b64.split(",", 1)[1]
                raw = base64.b64decode(b64)
                if len(raw) > MAX_JSON_BODY:
                    self.send_json({"ok": False, "error": "Bundle too large."}, 400)
                    return
                buf = io.BytesIO(raw)
                with zipfile.ZipFile(buf, "r") as zf:
                    names = zf.namelist()
                    if "watchface.bin" not in names:
                        self.send_json({"ok": False, "error": "Bundle has no watchface.bin."}, 400)
                        return
                    bin_raw = zf.read("watchface.bin")
                    if not valid_bin(bin_raw):
                        self.send_json({"ok": False, "error": "Bundle contains an invalid .bin."}, 400)
                        return
                    meta = {}
                    if "meta.json" in names:
                        try:
                            meta = json.loads(zf.read("meta.json").decode("utf-8"))
                        except Exception:
                            pass
                    name = (meta.get("name") or "Shared Watchface").strip()[:80]
                    pid = slugify(name)
                    pdir = safe_preset_dir(pid)
                    if not pdir:
                        self.send_json({"ok": False, "error": "Invalid bundle name."}, 400)
                        return
                    if os.path.exists(pdir):
                        pdir = os.path.join(PRESETS_DIR, f"{pid}_{int(time.time()) % 10000}")
                    os.makedirs(pdir, exist_ok=True)
                    for fname in BUNDLE_FILES:
                        if fname in names and fname != "meta.json":
                            with open(os.path.join(pdir, fname), "wb") as f:
                                f.write(zf.read(fname))
                    with open(os.path.join(pdir, "meta.json"), "w", encoding="utf-8") as f:
                        json.dump({"name": name, "subtitle": meta.get("subtitle", "Shared Watch 4S dial"),
                                   "created_at": int(time.time())}, f, indent=2)
                self.send_json({"ok": True, "id": os.path.basename(pdir),
                                "message": f"Imported shared dial '{name}'."})
            except Exception as exc:
                self.send_json({"ok": False, "error": f"Bundle import failed: {exc}"}, 400)

        elif path == "/api/upload-font":
            try:
                fname = os.path.basename((body.get("filename") or "custom.ttf").strip())
                if not fname.lower().endswith((".ttf", ".otf", ".ttc")):
                    self.send_json({"ok": False, "error": "Only .ttf, .otf or .ttc fonts are supported."}, 400)
                    return
                b64 = body.get("font_data", "")
                if "," in b64:
                    b64 = b64.split(",", 1)[1]
                raw = base64.b64decode(b64)
                if len(raw) > MAX_FONT_BYTES:
                    self.send_json({"ok": False, "error": "Font too large (limit 8 MB)."}, 400)
                    return
                if not raw.startswith(FONT_MAGICS):
                    self.send_json({"ok": False, "error": "That file is not a recognized TrueType/OpenType font."}, 400)
                    return
                with open(os.path.join(FONTS_DIR, fname), "wb") as f:
                    f.write(raw)
                self.send_json({"ok": True, "path": os.path.join(FONTS_DIR, fname),
                                "message": f"Font '{fname}' added."})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, 500)

        elif path == "/api/push-preset":
            pid = body.get("id", "")
            pdir = safe_preset_dir(pid)
            bin_path = os.path.join(pdir, "watchface.bin") if pdir else ""
            if not bin_path or not os.path.exists(bin_path):
                self.send_json({"ok": False, "error": "Preset not found."}, 404)
                return
            if not check_adb()["connected"]:
                self.send_json({"ok": False, "error": "No phone connected — check USB and USB debugging."}, 400)
                return
            subprocess.run(["adb", "shell", "mkdir", "-p",
                            "/sdcard/Android/data/com.yingsheng.hayloufun/cache"], capture_output=True)
            if push_bin_to_phone(bin_path):
                self.send_json({"ok": True, "message": "Pushed! Open Haylou Fun → Dial Center → install any free cloud dial."})
            else:
                self.send_json({"ok": False, "error": "ADB push failed — unlock the phone and try again."}, 500)

        elif path == "/api/install-apk":
            if not os.path.isfile(MODDED_APK):
                self.send_json({"ok": False, "error": "Modded APK not found — build it first with scripts/patch_and_build_apk.py."}, 404)
                return
            status = check_adb()
            if not status["connected"]:
                self.send_json({"ok": False, "error": "No phone connected — check USB and USB debugging."}, 400)
                return
            try:
                res = subprocess.run(["adb", "install", "-r", MODDED_APK],
                                     capture_output=True, text=True, timeout=180)
                if res.returncode == 0:
                    subprocess.run(["adb", "shell", "am", "start", "-n",
                                    "com.yingsheng.hayloufun/com.liesheng.hayloufun.SplashActivity"],
                                   capture_output=True)
                    self.send_json({"ok": True, "message": "Modded Haylou Fun installed & launched."})
                else:
                    self.send_json({"ok": False, "error": (res.stderr or res.stdout).strip()[:400]}, 500)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, 500)
        else:
            self.send_json({"ok": False, "error": "Not found."}, 404)


def main():
    try:
        server = ThreadingHTTPServer((HOST, PORT), StudioHandler)
    except OSError as exc:
        print(f"Cannot start Studio on {HOST}:{PORT}: {exc}")
        print("Another process may be using the port. Set STUDIO_PORT to a different value.")
        return
    url = f"http://{HOST}:{PORT}"
    print("=" * 60)
    print(f"  Haylou Watch 4S Studio running at {url}")
    print("  Press Ctrl+C to stop. Logs: set STUDIO_LOG=1")
    print("=" * 60)
    threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Studio…")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
