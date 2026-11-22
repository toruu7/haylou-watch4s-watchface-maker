"""
Haylou Watch 4S Watchface Studio — Phase A Pro Backend Server
Supports Multi-Layer Visual Designer, Live Pixel-Exact Preview, Font Upload,
Preset Edit/Duplicate/Import .bin, Omnitrix (OS/AF/Omniverse/5YL), and ADB Push.
"""

import base64
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STUDIO_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.abspath(os.path.join(STUDIO_DIR, ".."))
SCRIPTS_DIR = os.path.join(PROJECT_DIR, "scripts")
PRESETS_DIR = os.path.join(PROJECT_DIR, "presets")
FONTS_DIR = os.path.join(PROJECT_DIR, "fonts")
SAMPLES_DIR = os.path.join(PROJECT_DIR, "samples")
MODDED_APK = os.path.join(PROJECT_DIR, "haylou-fun-v4-0-8-noclock.apk")

sys.path.insert(0, SCRIPTS_DIR)
from watchface_bin_maker import push_bin_to_phone
from watchface_compiler import (
    compile_config_to_bin,
    decode_bin_preview,
    render_config_preview,
)

os.makedirs(PRESETS_DIR, exist_ok=True)
os.makedirs(FONTS_DIR, exist_ok=True)


def slugify(name):
    s = re.sub(r"[^a-zA-Z0-9_-]+", "_", name.strip()).strip("_").lower()
    return s or f"preset_{int(time.time())}"


def get_all_fonts():
    found = []
    # 1. User-uploaded custom fonts first
    if os.path.exists(FONTS_DIR):
        for fname in sorted(os.listdir(FONTS_DIR)):
            if fname.lower().endswith((".ttf", ".otf")):
                label = os.path.splitext(fname)[0] + " (Custom)"
                found.append({"label": label, "path": os.path.join(FONTS_DIR, fname)})

    # 2. Windows system fonts
    fonts_dir = r"C:\Windows\Fonts"
    candidates = [
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
    ]
    for label, fname in candidates:
        full = os.path.join(fonts_dir, fname)
        if os.path.exists(full):
            found.append({"label": label, "path": full})
    return found


def check_adb():
    try:
        res = subprocess.run(["adb", "devices", "-l"], capture_output=True, text=True, timeout=4)
        if res.returncode != 0:
            return {"connected": False, "detail": "ADB error"}
        for line in res.stdout.splitlines()[1:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "device":
                model = ""
                for p in parts[2:]:
                    if p.startswith("model:"):
                        model = p.split(":", 1)[1]
                return {"connected": True, "serial": parts[0], "model": model or parts[0]}
            if len(parts) >= 2 and parts[1] == "unauthorized":
                return {"connected": False, "detail": "Phone unauthorized — tap Allow on phone"}
        return {"connected": False, "detail": "No phone connected via USB"}
    except Exception as e:
        return {"connected": False, "detail": str(e)}


def list_presets():
    items = []
    if not os.path.exists(PRESETS_DIR):
        return items
    for pid in sorted(os.listdir(PRESETS_DIR)):
        pdir = os.path.join(PRESETS_DIR, pid)
        meta_path = os.path.join(pdir, "meta.json")
        bin_path = os.path.join(pdir, "watchface.bin")
        if os.path.isdir(pdir) and os.path.exists(meta_path) and os.path.exists(bin_path):
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                meta["id"] = pid
                meta["size_kb"] = round(os.path.getsize(bin_path) / 1024.0, 1)
                meta["editable"] = os.path.exists(os.path.join(pdir, "config.json"))
                meta["preview_url"] = f"/presets/{pid}/preview.png?t={int(os.path.getmtime(bin_path))}"
                items.append(meta)
            except Exception:
                pass
    items.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    return items


def summarize_config(cfg):
    parts = []
    bg = cfg.get("background", {})
    if bg.get("mode") == "omnitrix":
        parts.append(f"Omnitrix ({bg.get('omni_style', 'alien_force').upper()})")
    elif bg.get("mode") == "image":
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
    if len(parts) == 1:
        parts.append("Pure Image · No Clock")
    return " · ".join(parts)


def resolve_config_image(cfg, temp_dir=None):
    """If config.background has inline image_data (base64), write it to a file and set image_path."""
    cfg_copy = json.loads(json.dumps(cfg))
    bg = cfg_copy.get("background", {})
    img_b64 = bg.pop("image_data", None)
    if bg.get("mode") == "image" and img_b64:
        if "," in img_b64:
            img_b64 = img_b64.split(",", 1)[1]
        out_dir = temp_dir or tempfile.gettempdir()
        img_path = os.path.join(out_dir, "source.png")
        with open(img_path, "wb") as f:
            f.write(base64.b64decode(img_b64))
        bg["image_path"] = img_path
    return cfg_copy


class StudioHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def send_json(self, obj, status=200):
        raw = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def send_file(self, path, content_type):
        if not os.path.exists(path):
            self.send_error(404)
            return
        with open(path, "rb") as f:
            raw = f.read()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(raw)

    def read_json_body(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length > 0 else b"{}"
        return json.loads(raw.decode("utf-8"))

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/index.html":
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
            pdir = os.path.join(PRESETS_DIR, pid)
            cfg_path = os.path.join(pdir, "config.json")
            meta_path = os.path.join(pdir, "meta.json")
            if not pid or ".." in pid or not os.path.exists(cfg_path):
                self.send_json({"ok": False, "error": "Editable config not found for this preset."}, 404)
                return
            with open(cfg_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            name = pid
            if os.path.exists(meta_path):
                with open(meta_path, "r", encoding="utf-8") as f:
                    name = json.load(f).get("name", pid)
            # Include source image as data URI if present
            src_img = os.path.join(pdir, "source.png")
            if os.path.exists(src_img):
                with open(src_img, "rb") as f:
                    cfg.setdefault("background", {})["image_data"] = "data:image/png;base64," + base64.b64encode(f.read()).decode("ascii")
            self.send_json({"ok": True, "id": pid, "name": name, "config": cfg})
        elif path.startswith("/presets/"):
            rel = path[len("/presets/"):].strip("/")
            parts = rel.split("/")
            if len(parts) == 2 and parts[1] == "preview.png" and ".." not in parts[0]:
                self.send_file(os.path.join(PRESETS_DIR, parts[0], "preview.png"), "image/png")
            else:
                self.send_error(404)
        else:
            self.send_error(404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        try:
            body = self.read_json_body()
        except Exception as e:
            self.send_json({"ok": False, "error": f"Invalid JSON: {e}"}, 400)
            return

        if path == "/api/render-preview":
            try:
                cfg = body.get("config", {})
                with tempfile.TemporaryDirectory() as td:
                    resolved = resolve_config_image(cfg, temp_dir=td)
                    img = render_config_preview(resolved)
                buf = io.BytesIO()
                img.save(buf, format="PNG")
                raw = buf.getvalue()
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, 500)

        elif path == "/api/save-preset":
            try:
                name = body.get("name", "").strip() or "Custom Watchface"
                edit_id = body.get("edit_id", "").strip()
                cfg = body.get("config", {})
                auto_push = bool(body.get("push", False))

                if edit_id and ".." not in edit_id and os.path.isdir(os.path.join(PRESETS_DIR, edit_id)):
                    pid = edit_id
                else:
                    pid = slugify(name)
                    if os.path.exists(os.path.join(PRESETS_DIR, pid)):
                        pid = f"{pid}_{int(time.time()) % 10000}"

                pdir = os.path.join(PRESETS_DIR, pid)
                os.makedirs(pdir, exist_ok=True)

                resolved = resolve_config_image(cfg, temp_dir=pdir)
                # Preserve existing source.png if editing an image preset without re-uploading
                if resolved.get("background", {}).get("mode") == "image" and not resolved["background"].get("image_path"):
                    existing_src = os.path.join(pdir, "source.png")
                    if os.path.exists(existing_src):
                        resolved["background"]["image_path"] = existing_src

                bin_path = os.path.join(pdir, "watchface.bin")
                prev_path = os.path.join(pdir, "preview.png")
                compile_config_to_bin(resolved, bin_path, save_preview_path=prev_path)

                with open(os.path.join(pdir, "config.json"), "w", encoding="utf-8") as f:
                    json.dump(resolved, f, indent=2)

                meta = {
                    "name": name,
                    "subtitle": summarize_config(resolved),
                    "created_at": int(time.time()),
                }
                with open(os.path.join(pdir, "meta.json"), "w", encoding="utf-8") as f:
                    json.dump(meta, f, indent=2)

                pushed = False
                msg = f"Saved '{name}' to Presets!"
                if auto_push:
                    subprocess.run(["adb", "shell", "mkdir -p /sdcard/Android/data/com.yingsheng.hayloufun/cache"], capture_output=True)
                    pushed = push_bin_to_phone(bin_path)
                    msg = (
                        f"Saved & pushed '{name}'! Open Haylou Fun -> Dial Center -> tap Install on any free cloud dial."
                        if pushed
                        else f"Saved '{name}', but ADB push failed (check USB connection)."
                    )
                self.send_json({"ok": True, "id": pid, "pushed": pushed, "message": msg})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, 500)

        elif path == "/api/duplicate-preset":
            pid = body.get("id", "")
            src_dir = os.path.join(PRESETS_DIR, pid)
            if not pid or ".." in pid or not os.path.isdir(src_dir):
                self.send_json({"ok": False, "error": "Preset not found"}, 404)
                return
            new_id = f"{pid}_copy_{int(time.time()) % 10000}"
            dst_dir = os.path.join(PRESETS_DIR, new_id)
            shutil.copytree(src_dir, dst_dir)
            meta_path = os.path.join(dst_dir, "meta.json")
            if os.path.exists(meta_path):
                with open(meta_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                meta["name"] = meta.get("name", pid) + " (Copy)"
                meta["created_at"] = int(time.time())
                with open(meta_path, "w", encoding="utf-8") as f:
                    json.dump(meta, f, indent=2)
            self.send_json({"ok": True, "id": new_id, "message": "Preset duplicated!"})

        elif path == "/api/import-bin":
            try:
                name = body.get("name", "").strip() or "Imported Watchface"
                b64 = body.get("bin_data", "")
                if "," in b64:
                    b64 = b64.split(",", 1)[1]
                raw = base64.b64decode(b64)
                pid = slugify(name)
                if os.path.exists(os.path.join(PRESETS_DIR, pid)):
                    pid = f"{pid}_{int(time.time()) % 10000}"
                pdir = os.path.join(PRESETS_DIR, pid)
                os.makedirs(pdir, exist_ok=True)
                bin_path = os.path.join(pdir, "watchface.bin")
                with open(bin_path, "wb") as f:
                    f.write(raw)
                prev = decode_bin_preview(bin_path)
                prev.save(os.path.join(pdir, "preview.png"))
                with open(os.path.join(pdir, "meta.json"), "w", encoding="utf-8") as f:
                    json.dump({
                        "name": name,
                        "subtitle": "Imported Watch 4S .bin",
                        "created_at": int(time.time()),
                    }, f, indent=2)
                self.send_json({"ok": True, "id": pid, "message": f"Imported '{name}' into Presets!"})
            except Exception as e:
                self.send_json({"ok": False, "error": f"Failed to import .bin: {e}"}, 400)

        elif path == "/api/upload-font":
            try:
                fname = os.path.basename(body.get("filename", "custom.ttf"))
                if not fname.lower().endswith((".ttf", ".otf")):
                    self.send_json({"ok": False, "error": "Only .ttf or .otf fonts are supported."}, 400)
                    return
                b64 = body.get("font_data", "")
                if "," in b64:
                    b64 = b64.split(",", 1)[1]
                out_path = os.path.join(FONTS_DIR, fname)
                with open(out_path, "wb") as f:
                    f.write(base64.b64decode(b64))
                self.send_json({"ok": True, "path": out_path, "message": f"Font '{fname}' added!"})
            except Exception as e:
                self.send_json({"ok": False, "error": str(e)}, 500)

        elif path == "/api/push-preset":
            pid = body.get("id", "")
            bin_path = os.path.join(PRESETS_DIR, pid, "watchface.bin")
            if not pid or ".." in pid or not os.path.exists(bin_path):
                self.send_json({"ok": False, "error": "Preset not found"}, 404)
                return
            subprocess.run(["adb", "shell", "mkdir -p /sdcard/Android/data/com.yingsheng.hayloufun/cache"], capture_output=True)
            ok = push_bin_to_phone(bin_path)
            if ok:
                self.send_json({"ok": True, "message": "Pushed! Open Haylou Fun -> Dial Center -> tap Install on any free cloud dial."})
            else:
                self.send_json({"ok": False, "error": "ADB push failed. Make sure phone is connected & unlocked."})

        elif path == "/api/delete-preset":
            pid = body.get("id", "")
            pdir = os.path.join(PRESETS_DIR, pid)
            if not pid or ".." in pid or not os.path.isdir(pdir):
                self.send_json({"ok": False, "error": "Preset not found"}, 404)
                return
            shutil.rmtree(pdir, ignore_errors=True)
            self.send_json({"ok": True})

        elif path == "/api/install-apk":
            if not os.path.exists(MODDED_APK):
                self.send_json({"ok": False, "error": "Modded APK not found."})
                return
            res = subprocess.run(["adb", "install", "-r", MODDED_APK], capture_output=True, text=True)
            if res.returncode == 0:
                subprocess.run(["adb", "shell", "am", "start", "-n", "com.yingsheng.hayloufun/com.liesheng.hayloufun.SplashActivity"], capture_output=True)
                self.send_json({"ok": True, "message": "Modded Haylou Fun APK installed & launched!"})
            else:
                self.send_json({"ok": False, "error": (res.stderr or res.stdout).strip()})

        else:
            self.send_error(404)


def main():
    port = 8466
    server = ThreadingHTTPServer(("127.0.0.1", port), StudioHandler)
    url = f"http://127.0.0.1:{port}"
    print("=" * 60)
    print(f"  Haylou Watch 4S Studio (Phase A Pro) running at {url}")
    print("  Press Ctrl+C to stop.")
    print("=" * 60)
    threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()


if __name__ == "__main__":
    main()
