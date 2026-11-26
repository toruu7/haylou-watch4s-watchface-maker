"""
Haylou Watch 4S Studio — local Studio backend.

Serves the browser designer, compiles .bin files, manages presets & multi-layer
assets (custom hands, tap-switch scenes, PNG stickers, animated GIF zones), and
bridges ADB for pushing dials / installing the modded companion app.

Runs on 127.0.0.1 only. No network exposure, no telemetry, no accounts.
"""

import base64
import glob
import io
import json
import os
import re
import shutil
import socket
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
BUILTIN_ASSETS_DIR = os.path.join(STUDIO_DIR, "assets")
PROJECT_DIR = os.path.abspath(os.path.join(STUDIO_DIR, ".."))
SCRIPTS_DIR = os.path.join(PROJECT_DIR, "scripts")
PRESETS_DIR = os.path.join(PROJECT_DIR, "presets")
FONTS_DIR = os.path.join(PROJECT_DIR, "fonts")
MODDED_APK_CANDIDATES = (
    os.path.join(PROJECT_DIR, "haylou-fun-v4-0-8-full-health.apk"),
    os.path.join(PROJECT_DIR, "haylou-fun-v4-0-8-noclock.apk"),
)
MODDED_APK = MODDED_APK_CANDIDATES[1]

HOST = "127.0.0.1"
PORT = int(os.environ.get("STUDIO_PORT", "8466"))

MAX_JSON_BODY = 64 * 1024 * 1024
MAX_BIN_BYTES = 8 * 1024 * 1024
MAX_FONT_BYTES = 8 * 1024 * 1024
MAX_IMAGE_BYTES = 16 * 1024 * 1024
FONT_MAGICS = (b"\x00\x01\x00\x00", b"true", b"OTTO", b"ttcf", b"wOFF", b"wOF2")
KNOWN_BIN_FLAGS = (
    0x0002, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009, 0x000A, 0x000D,
    0x000E, 0x000F, 0x0010, 0x0011, 0x0012, 0x0014, 0x0015, 0x0018,
    0x001A, 0x001B, 0x001C, 0x001D, 0x001F, 0x0023, 0x0025, 0x002E,
)
BUNDLE_FILES = (
    "meta.json", "config.json", "preview.png",
    "source.png", "source.jpg", "source.gif", "source.webp", "watchface.bin",
)
SAFE_ASSET_EXTS = (".png", ".jpg", ".jpeg", ".gif", ".webp")

sys.path.insert(0, SCRIPTS_DIR)
from watchface_bin_maker import find_adb, push_bin_to_phone
from watchface_compiler import (
    MAX_WATCH_BIN_BYTES,
    compile_config_to_bin,
    decode_bin_preview,
    inspect_watchface_bin,
    normalize_gauges,
    render_config_animated_preview,
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


def _path_within(path, root):
    if not path or not root:
        return False
    try:
        rp = os.path.realpath(path)
        rr = os.path.realpath(root)
        return rp != rr and os.path.commonpath([rr, rp]) == rr
    except Exception:
        return False


def valid_bin(raw):
    if not (16 <= len(raw) <= MAX_BIN_BYTES):
        return False
    flags, magic = struct.unpack_from("<HH", raw, 0)
    return (flags in KNOWN_BIN_FLAGS or 0x0001 <= flags <= 0x00FF) and magic == 0xFFFF


def resolve_modded_apk():
    for cand in MODDED_APK_CANDIDATES:
        if os.path.isfile(cand):
            return cand
    return MODDED_APK


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

    adb = find_adb()
    result = {"connected": False, "detail": "No phone connected via USB"}
    try:
        res = subprocess.run([adb, "devices", "-l"], capture_output=True, text=True, timeout=10)
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
                        [adb, "-s", serial, "shell", "pm", "path", "com.yingsheng.hayloufun"],
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
    elif mode == "animated_gif":
        parts.append(f"Animated GIF ({bg.get('anim_frames', 8)}f @ {bg.get('anim_fps', 4)}fps)")
    elif mode == "image":
        parts.append("Custom Image")
    else:
        parts.append("Gradient/Solid")

    ts = cfg.get("tap_switch", {})
    if ts.get("enabled"):
        if ts.get("mode") == "custom_images" and isinstance(ts.get("frames"), list) and len(ts["frames"]) >= 2:
            parts.append(f"Tap-Switch ({len(ts['frames'])} scenes)")
        else:
            parts.append(f"Tap-Switch ({ts.get('mode', 'day_night').replace('_', ' ')})")

    bz = cfg.get("bezel", {})
    if bz.get("enabled"):
        parts.append(f"Bezel ({bz.get('style', 'baton').replace('_', ' ')})")

    clk = cfg.get("digital_clock", {})
    if clk.get("enabled"):
        s = f"Digital ({clk.get('layout', 'horizontal')})"
        if clk.get("show_seconds"):
            s += "+Sec"
        if clk.get("show_ampm"):
            s += "+AM/PM"
        parts.append(s)

    dt = cfg.get("date", {})
    if dt.get("enabled"):
        s = f"Date ({dt.get('format', 'MM/DD')})"
        if dt.get("show_year"):
            s += "+Yr"
        parts.append(s)

    if cfg.get("weather", {}).get("enabled"):
        parts.append("Weather")
    if cfg.get("bluetooth", {}).get("enabled"):
        parts.append("BT")

    if cfg.get("analog_hands", {}).get("enabled"):
        parts.append(f"Hands ({cfg['analog_hands'].get('style', 'omnitrix')})")

    gauges = [g for g in normalize_gauges(cfg) if g.get("enabled", True)]
    if gauges:
        if len(gauges) == 1:
            g = gauges[0]
            if g.get("style") == "omnitrix_low_red":
                parts.append("Low-Batt Red (<50%)")
            else:
                parts.append(f"{g.get('metric', 'battery').capitalize()} ({g.get('style', 'ring')})")
        else:
            parts.append(f"{len(gauges)} Gauges")

    if cfg.get("weekday", {}).get("enabled"):
        parts.append("Weekday")

    telem = cfg.get("telemetry", {})
    if telem.get("enabled"):
        tlist = []
        for k, lbl in (("steps", "Steps"), ("heart_rate", "HR"), ("calories", "Cal"), ("distance", "Dist"), ("battery_pct", "Batt%")):
            if isinstance(telem.get(k), dict) and telem[k].get("enabled"):
                tlist.append(lbl)
        if telem.get("show_distance_unit") or (isinstance(telem.get("distance_unit"), dict) and telem["distance_unit"].get("enabled")):
            tlist.append("km/mi")
        if tlist:
            parts.append("Live " + "/".join(tlist))

    anims = [a for a in (cfg.get("anim_sprites") or []) if isinstance(a, dict) and a.get("enabled", True)]
    if anims:
        parts.append(f"{len(anims)} GIF Zone" + ("s" if len(anims) != 1 else ""))
    ovs = [o for o in (cfg.get("overlays") or []) if isinstance(o, dict) and o.get("enabled", True)]
    if ovs:
        parts.append(f"{len(ovs)} Sticker" + ("s" if len(ovs) != 1 else ""))
    txts = [t for t in (cfg.get("text_labels") or []) if isinstance(t, dict) and t.get("enabled", True) and str(t.get("text", "")).strip()]
    if txts:
        parts.append(f"{len(txts)} Text")

    if len(parts) == 1 and mode != "animated_gif":
        parts.append("Pure Image · No Clock")
    return " · ".join(parts)


def _detect_image_ext(raw):
    if raw[:6] in (b"GIF87a", b"GIF89a"):
        return ".gif"
    if raw[:4] == b"RIFF" and raw[8:12] == b"WEBP":
        return ".webp"
    if raw[:3] == b"\xff\xd8\xff":
        return ".jpg"
    return ".png"


def _mime_for_path(path):
    ext = os.path.splitext(path)[1].lower()
    return {
        ".gif": "image/gif",
        ".webp": "image/webp",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".png": "image/png",
    }.get(ext, "image/png")


def _file_to_data_url(path):
    if not path or not os.path.isfile(path):
        return None
    with open(path, "rb") as f:
        raw = f.read()
    return f"data:{_mime_for_path(path)};base64," + base64.b64encode(raw).decode("ascii")


def _write_data_url_asset(b64_str, out_dir, stem):
    """Decode base64/data-URL image and write to out_dir/<stem><ext>. Returns file path."""
    if "," in b64_str:
        b64_str = b64_str.split(",", 1)[1]
    raw = base64.b64decode(b64_str)
    if len(raw) > MAX_IMAGE_BYTES:
        raise ValueError("Image too large (limit 16 MB).")
    os.makedirs(out_dir, exist_ok=True)
    ext = _detect_image_ext(raw)
    safe_stem = slugify(stem)[:48]
    dest = os.path.join(out_dir, safe_stem + ext)
    with open(dest, "wb") as f:
        f.write(raw)
    return dest


def _resolve_builtin_asset(path):
    """Resolve 'builtin://<relpath>' safely inside studio/assets/."""
    if not isinstance(path, str) or not path.startswith("builtin://"):
        return None
    rel = path[len("builtin://"):].replace("\\", "/").lstrip("/")
    if not rel or ".." in rel.split("/"):
        return None
    if os.path.splitext(rel)[1].lower() not in SAFE_ASSET_EXTS:
        return None
    cand = os.path.realpath(os.path.join(BUILTIN_ASSETS_DIR, *rel.split("/")))
    if os.path.isfile(cand) and _path_within(cand, BUILTIN_ASSETS_DIR):
        return cand
    return None


def _safe_existing_asset(path, persist_dir=None):
    """Keep an existing image_path only if it lives safely inside PRESETS_DIR, persist_dir, or BUILTIN_ASSETS_DIR."""
    if not isinstance(path, str) or not path:
        return None
    builtin = _resolve_builtin_asset(path)
    if builtin:
        return builtin
    if not os.path.isfile(path):
        return None
    if persist_dir and _path_within(path, persist_dir):
        return path
    if _path_within(path, PRESETS_DIR) or _path_within(path, BUILTIN_ASSETS_DIR):
        return path
    return None


def _persist_existing_asset(existing, persist_dir, target_dir, target_name=None):
    """Copy an external/builtin existing asset into persist_dir so saved presets & .face.zip bundles are self-contained."""
    if not existing or not persist_dir or _path_within(existing, persist_dir):
        return existing
    os.makedirs(target_dir, exist_ok=True)
    name = target_name or os.path.basename(existing)
    dest = os.path.join(target_dir, name)
    if os.path.realpath(existing) != os.path.realpath(dest):
        shutil.copy2(existing, dest)
    return dest


def resolve_config_assets(cfg, temp_dir=None, filename=None, persist_dir=None):
    """
    Decode all inline base64 `*_image_data` fields (background, tap_switch frames,
    custom analog hands/cap, PNG overlays, animated GIF zones, gauge images) to files on disk
    and replace them with clean `*_image_path` references.
    """
    cfg_copy = json.loads(json.dumps(cfg))
    out_root = persist_dir or temp_dir or tempfile.gettempdir()
    assets_dir = os.path.join(out_root, "assets") if persist_dir else out_root

    # 1. Background image / GIF
    bg = cfg_copy.get("background")
    if isinstance(bg, dict):
        img_b64 = bg.pop("image_data", None)
        if bg.get("mode") in ("image", "animated_gif") and img_b64:
            if persist_dir:
                for old_ext in (".png", ".jpg", ".gif", ".webp"):
                    old_p = os.path.join(persist_dir, "source" + old_ext)
                    if os.path.exists(old_p):
                        try:
                            os.remove(old_p)
                        except OSError:
                            pass
                stem = "source"
            else:
                stem = os.path.splitext(filename)[0] if filename else f"studio_source_{uuid.uuid4().hex[:10]}"
            bg["image_path"] = _write_data_url_asset(img_b64, out_root, stem)
        else:
            existing = _safe_existing_asset(bg.get("image_path"), persist_dir)
            if existing:
                ext = os.path.splitext(existing)[1].lower() or ".png"
                bg["image_path"] = _persist_existing_asset(existing, persist_dir, out_root, target_name="source" + ext)
            elif persist_dir and bg.get("mode") in ("image", "animated_gif"):
                bg.pop("image_path", None)
                for cand in ("source.gif", "source.webp", "source.png", "source.jpg"):
                    cp = os.path.join(persist_dir, cand)
                    if os.path.isfile(cp):
                        bg["image_path"] = cp
                        break
            else:
                bg.pop("image_path", None)

    # 2. Tap-to-Switch custom scene frames (01 1a)
    ts = cfg_copy.get("tap_switch")
    if isinstance(ts, dict) and isinstance(ts.get("frames"), list):
        for idx, fr in enumerate(ts["frames"][:6]):
            if not isinstance(fr, dict):
                continue
            fr.pop("thumb_url", None)
            b64 = fr.pop("image_data", None)
            if b64:
                stem = f"tap_{idx}_{uuid.uuid4().hex[:6]}" if not persist_dir else f"tap_{idx}"
                fr["image_path"] = _write_data_url_asset(b64, assets_dir, stem)
            else:
                existing = _safe_existing_asset(fr.get("image_path"), persist_dir)
                if existing:
                    fr["image_path"] = _persist_existing_asset(existing, persist_dir, assets_dir)
                else:
                    fr.pop("image_path", None)

    # 3. Custom Analog Hands + Center Cap PNGs (01 0a / 01 00)
    hands = cfg_copy.get("analog_hands")
    if isinstance(hands, dict):
        for role in ("hour", "min", "sec", "cap"):
            dk = f"{role}_image_data"
            pk = f"{role}_image_path"
            b64 = hands.pop(dk, None)
            if b64:
                stem = f"hand_{role}_{uuid.uuid4().hex[:6]}" if not persist_dir else f"hand_{role}"
                hands[pk] = _write_data_url_asset(b64, assets_dir, stem)
            else:
                existing = _safe_existing_asset(hands.get(pk), persist_dir)
                if existing:
                    hands[pk] = _persist_existing_asset(existing, persist_dir, assets_dir)
                else:
                    hands.pop(pk, None)

    # 4. Custom PNG Overlay / Sticker layers (01 00)
    overlays = cfg_copy.get("overlays")
    if isinstance(overlays, list):
        for idx, ov in enumerate(overlays[:12]):
            if not isinstance(ov, dict):
                continue
            b64 = ov.pop("image_data", None)
            oid = slugify(str(ov.get("id") or f"ov_{idx + 1}"))
            if b64:
                stem = f"overlay_{oid}_{uuid.uuid4().hex[:6]}" if not persist_dir else f"overlay_{oid}"
                ov["image_path"] = _write_data_url_asset(b64, assets_dir, stem)
            else:
                existing = _safe_existing_asset(ov.get("image_path"), persist_dir)
                if existing:
                    ov["image_path"] = _persist_existing_asset(existing, persist_dir, assets_dir)
                else:
                    ov.pop("image_path", None)

    # 5. Multi-Zone Animated Sprites (01 2e)
    anims = cfg_copy.get("anim_sprites")
    if isinstance(anims, list):
        for idx, sp in enumerate(anims[:4]):
            if not isinstance(sp, dict):
                continue
            b64 = sp.pop("image_data", None)
            aid = slugify(str(sp.get("id") or f"anim_{idx + 1}"))
            if b64:
                stem = f"anim_{aid}_{uuid.uuid4().hex[:6]}" if not persist_dir else f"anim_{aid}"
                sp["image_path"] = _write_data_url_asset(b64, assets_dir, stem)
            else:
                existing = _safe_existing_asset(sp.get("image_path"), persist_dir)
                if existing:
                    sp["image_path"] = _persist_existing_asset(existing, persist_dir, assets_dir)
                else:
                    sp.pop("image_path", None)

    # 6. Optional Gauge Overlay Images (e.g. omnitrix_low_red transparent-bezel Red Timeout)
    gauges = cfg_copy.get("gauges")
    if isinstance(gauges, list):
        for idx, g in enumerate(gauges[:4]):
            if not isinstance(g, dict):
                continue
            b64 = g.pop("image_data", None)
            gid = slugify(str(g.get("id") or f"g_{idx + 1}"))
            if b64:
                stem = f"gauge_{gid}_{uuid.uuid4().hex[:6]}" if not persist_dir else f"gauge_{gid}"
                g["image_path"] = _write_data_url_asset(b64, assets_dir, stem)
            else:
                existing = _safe_existing_asset(g.get("image_path"), persist_dir)
                if existing:
                    g["image_path"] = _persist_existing_asset(existing, persist_dir, assets_dir)
                else:
                    g.pop("image_path", None)

    return cfg_copy


resolve_config_image = resolve_config_assets


def hydrate_config_assets(cfg, pdir):
    """Inline all saved preset image files back into `*_image_data` data URLs for editing in Studio."""
    out = json.loads(json.dumps(cfg))

    # Background source.*
    bg = out.setdefault("background", {})
    for cand in ("source.gif", "source.webp", "source.png", "source.jpg"):
        src_img = os.path.join(pdir, cand)
        if os.path.isfile(src_img):
            data_url = _file_to_data_url(src_img)
            if data_url:
                bg["image_data"] = data_url
            break

    def resolve_in_pdir(path_val):
        if not isinstance(path_val, str) or not path_val:
            return None
        if os.path.isfile(path_val) and _path_within(path_val, pdir):
            return path_val
        # Fallback to matching basename under pdir/assets/
        base = os.path.basename(path_val)
        cand = os.path.join(pdir, "assets", base)
        if os.path.isfile(cand) and _path_within(cand, pdir):
            return cand
        return None

    ts = out.get("tap_switch")
    if isinstance(ts, dict) and isinstance(ts.get("frames"), list):
        for fr in ts["frames"]:
            if isinstance(fr, dict):
                rp = resolve_in_pdir(fr.get("image_path"))
                if rp:
                    fr["image_data"] = _file_to_data_url(rp)

    hands = out.get("analog_hands")
    if isinstance(hands, dict):
        for role in ("hour", "min", "sec", "cap"):
            rp = resolve_in_pdir(hands.get(f"{role}_image_path"))
            if rp:
                hands[f"{role}_image_data"] = _file_to_data_url(rp)

    for list_key in ("overlays", "anim_sprites"):
        items = out.get(list_key)
        if isinstance(items, list):
            for it in items:
                if isinstance(it, dict):
                    rp = resolve_in_pdir(it.get("image_path"))
                    if rp:
                        it["image_data"] = _file_to_data_url(rp)

    return out


def rebase_config_paths(cfg, new_dir):
    """Update stored image_path fields in a duplicated/imported preset config to point inside new_dir."""
    out = json.loads(json.dumps(cfg))

    def map_path(old_p, check_root=True):
        if not isinstance(old_p, str) or not old_p:
            return old_p
        base = os.path.basename(old_p)
        if check_root:
            p_root = os.path.join(new_dir, base)
            if os.path.isfile(p_root):
                return p_root
        p_asset = os.path.join(new_dir, "assets", base)
        if os.path.isfile(p_asset):
            return p_asset
        return old_p

    if isinstance(out.get("background"), dict) and out["background"].get("image_path"):
        out["background"]["image_path"] = map_path(out["background"]["image_path"], check_root=True)
    if isinstance(out.get("tap_switch"), dict) and isinstance(out["tap_switch"].get("frames"), list):
        for fr in out["tap_switch"]["frames"]:
            if isinstance(fr, dict) and fr.get("image_path"):
                fr["image_path"] = map_path(fr["image_path"], check_root=False)
    if isinstance(out.get("analog_hands"), dict):
        for role in ("hour", "min", "sec", "cap"):
            pk = f"{role}_image_path"
            if out["analog_hands"].get(pk):
                out["analog_hands"][pk] = map_path(out["analog_hands"][pk], check_root=False)
    for list_key in ("overlays", "anim_sprites", "gauges"):
        if isinstance(out.get(list_key), list):
            for it in out[list_key]:
                if isinstance(it, dict) and it.get("image_path"):
                    it["image_path"] = map_path(it["image_path"], check_root=False)
    return out


def default_config_for(pid, meta):
    """Auto-migrate an imported legacy preset that has no config.json."""
    if meta.get("type") == "omnitrix" or "omnitrix" in pid.lower():
        return {
            "background": {"mode": "omnitrix", "omni_style": "alien_force", "omni_hex": "#39ff14",
                           "omni_glow": 1.0, "omni_ticks": True, "brightness": 100, "vignette": 0},
            "digital_clock": {"enabled": False},
            "analog_hands": {"enabled": True, "style": "omnitrix", "color": "#39ff14",
                             "accent_color": "#ebffe6", "show_seconds": True, "center_cap": False},
            "gauges": [{"id": "g1", "enabled": True, "kind": "progress", "metric": "battery",
                        "style": "ring", "color": "#39ff14", "thickness": 6, "radius_inset": 4}],
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
        "gauges": [],
        "weekday": {"enabled": False},
    }


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #

class StudioHandler(BaseHTTPRequestHandler):
    server_version = "Studio/2.0"

    def log_message(self, fmt, *args):
        if os.environ.get("STUDIO_LOG"):
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def send_json(self, obj, status=200):
        raw = json.dumps(obj).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass

    def send_bytes(self, raw, content_type, filename=None):
        try:
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Content-Type-Options", "nosniff")
            if filename:
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.end_headers()
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass

    def send_file(self, path, content_type):
        if not os.path.isfile(path):
            self.send_json({"ok": False, "error": "Not found."}, 404)
            return
        with open(path, "rb") as f:
            self.send_bytes(f.read(), content_type)

    def read_json_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > MAX_JSON_BODY:
            raise ValueError("Request too large (limit 64 MB).")
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
        elif path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
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
            hydrated = hydrate_config_assets(cfg, pdir)
            self.send_json({"ok": True, "id": pid, "name": meta.get("name", pid), "config": hydrated})
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
                    adir = os.path.join(pdir, "assets")
                    if os.path.isdir(adir):
                        for af in sorted(os.listdir(adir)):
                            afp = os.path.join(adir, af)
                            if os.path.isfile(afp) and os.path.splitext(af)[1].lower() in SAFE_ASSET_EXTS:
                                zf.write(afp, arcname=f"assets/{af}")
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, 500)
                return
            self.send_bytes(buf.getvalue(), "application/zip", f"{slugify(pid)}.face.zip")
        elif path.startswith("/builtin-assets/"):
            rel = urllib.parse.unquote(path[len("/builtin-assets/"):]).replace("\\", "/").lstrip("/")
            resolved = _resolve_builtin_asset("builtin://" + rel)
            if resolved:
                self.send_file(resolved, _mime_for_path(resolved))
                return
            self.send_json({"ok": False, "error": "Not found."}, 404)
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
                    resolved = resolve_config_assets(cfg, temp_dir=td)
                    anim_frames, dur_ms = render_config_animated_preview(resolved)
                    if anim_frames and len(anim_frames) >= 2:
                        buf = io.BytesIO()
                        pal_frames = [f.convert("RGBA") for f in anim_frames]
                        pal_frames[0].save(
                            buf,
                            format="GIF",
                            save_all=True,
                            append_images=pal_frames[1:],
                            duration=dur_ms,
                            loop=0,
                            disposal=2,
                        )
                        self.send_bytes(buf.getvalue(), "image/gif")
                        return
                    img = render_config_preview(resolved)
                buf = io.BytesIO()
                img.save(buf, format="PNG")
                self.send_bytes(buf.getvalue(), "image/png")
            except Exception as exc:
                self.send_json({"ok": False, "error": f"Preview failed: {exc}"}, 500)

        elif path == "/api/inspect-compile":
            try:
                cfg = body.get("config", {})
                with tempfile.TemporaryDirectory(prefix="studio_check_") as td:
                    resolved = resolve_config_assets(cfg, temp_dir=td)
                    out_bin = os.path.join(td, "check.bin")
                    compile_config_to_bin(resolved, out_bin)
                    raw_bin = open(out_bin, "rb").read()
                    info = inspect_watchface_bin(raw_bin)
                self.send_json({
                    "ok": bool(info.get("valid")),
                    "size_bytes": info.get("size_bytes", len(raw_bin)),
                    "size_kb": round(len(raw_bin) / 1024.0, 1),
                    "max_kb": round(MAX_WATCH_BIN_BYTES / 1024.0, 1),
                    "within_flash_budget": bool(info.get("within_flash_budget")),
                    "opcodes": info.get("opcodes", []),
                    "digit_tables": info.get("digit_tables", 0),
                    "has_anim_header": bool(info.get("has_anim_header")),
                    "errors": info.get("errors", []),
                })
            except Exception as exc:
                self.send_json({"ok": False, "error": f"Compile check failed: {exc}"}, 500)

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

                resolved = resolve_config_assets(cfg, persist_dir=pdir)

                bin_path = os.path.join(pdir, "watchface.bin")
                prev_path = os.path.join(pdir, "preview.png")
                compile_config_to_bin(resolved, bin_path, save_preview_path=prev_path)
                raw_bin = open(bin_path, "rb").read()
                info = inspect_watchface_bin(raw_bin)
                if not valid_bin(raw_bin) or not info["valid"]:
                    self.send_json({"ok": False, "error": f"Compiler produced an invalid .bin: {info.get('errors')}"}, 500)
                    return

                with open(os.path.join(pdir, "config.json"), "w", encoding="utf-8") as f:
                    json.dump(resolved, f, indent=2)
                with open(os.path.join(pdir, "meta.json"), "w", encoding="utf-8") as f:
                    json.dump({"name": name, "subtitle": summarize_config(resolved),
                               "created_at": int(time.time())}, f, indent=2)

                pushed = False
                size_kb = round(len(raw_bin) / 1024.0, 1)
                budget_note = "" if info["within_flash_budget"] else " (Warning: >1.3 MB flash budget)"
                message = f"Saved '{name}' ({size_kb} KB) to Presets.{budget_note}"
                if auto_push:
                    if not check_adb()["connected"]:
                        message = f"Saved '{name}' ({size_kb} KB), but no phone is connected — push skipped."
                    else:
                        adb = find_adb()
                        subprocess.run([adb, "shell", "mkdir", "-p",
                                        "/sdcard/Android/data/com.yingsheng.hayloufun/cache"],
                                       capture_output=True)
                        pushed = push_bin_to_phone(bin_path)
                        message = (f"Saved & pushed '{name}' ({size_kb} KB)! Open Haylou Fun → Dial Center → install any free cloud dial."
                                   if pushed else f"Saved '{name}', but the push failed — check the USB connection.")
                self.send_json({
                    "ok": True,
                    "id": os.path.basename(pdir),
                    "pushed": pushed,
                    "size_kb": size_kb,
                    "within_flash_budget": info["within_flash_budget"],
                    "opcodes": info.get("opcodes", []),
                    "message": message,
                })
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
                cfg_path = os.path.join(dst_dir, "config.json")
                if os.path.isfile(cfg_path):
                    with open(cfg_path, "r", encoding="utf-8") as f:
                        rebased = rebase_config_paths(json.load(f), dst_dir)
                    with open(cfg_path, "w", encoding="utf-8") as f:
                        json.dump(rebased, f, indent=2)
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
                            data = zf.read(fname)
                            if len(data) <= MAX_IMAGE_BYTES:
                                with open(os.path.join(pdir, fname), "wb") as f:
                                    f.write(data)
                    # Extract safe assets/* files
                    for entry in names:
                        norm = entry.replace("\\", "/")
                        if not norm.startswith("assets/") or norm.endswith("/"):
                            continue
                        sub = norm[len("assets/"):]
                        if "/" in sub or ".." in sub or not sub:
                            continue
                        if os.path.splitext(sub)[1].lower() not in SAFE_ASSET_EXTS:
                            continue
                        data = zf.read(entry)
                        if len(data) > MAX_IMAGE_BYTES:
                            continue
                        adir = os.path.join(pdir, "assets")
                        os.makedirs(adir, exist_ok=True)
                        with open(os.path.join(adir, sub), "wb") as f:
                            f.write(data)
                    cfg_path = os.path.join(pdir, "config.json")
                    if os.path.isfile(cfg_path):
                        try:
                            with open(cfg_path, "r", encoding="utf-8") as f:
                                rebased = rebase_config_paths(json.load(f), pdir)
                            with open(cfg_path, "w", encoding="utf-8") as f:
                                json.dump(rebased, f, indent=2)
                        except Exception:
                            pass
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
            adb = find_adb()
            subprocess.run([adb, "shell", "mkdir", "-p",
                            "/sdcard/Android/data/com.yingsheng.hayloufun/cache"], capture_output=True)
            if push_bin_to_phone(bin_path):
                self.send_json({"ok": True, "message": "Pushed! Open Haylou Fun → Dial Center → install any free cloud dial."})
            else:
                self.send_json({"ok": False, "error": "ADB push failed — unlock the phone and try again."}, 500)

        elif path == "/api/install-apk":
            apk_path = resolve_modded_apk()
            if not os.path.isfile(apk_path):
                self.send_json({"ok": False, "error": "Modded APK not found — build it first with scripts/patch_and_build_apk.py."}, 404)
                return
            status = check_adb()
            if not status["connected"]:
                self.send_json({"ok": False, "error": "No phone connected — check USB and USB debugging."}, 400)
                return
            adb = find_adb()
            try:
                res = subprocess.run([adb, "install", "-r", apk_path],
                                     capture_output=True, text=True, timeout=180)
                if res.returncode == 0:
                    subprocess.run([adb, "shell", "am", "start", "-n",
                                    "com.yingsheng.hayloufun/com.liesheng.hayloufun.SplashActivity"],
                                   capture_output=True)
                    self.send_json({"ok": True, "message": f"Installed & launched {os.path.basename(apk_path)}."})
                else:
                    self.send_json({"ok": False, "error": (res.stderr or res.stdout).strip()[:400]}, 500)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, 500)
        else:
            self.send_json({"ok": False, "error": "Not found."}, 404)


class ExclusiveThreadingHTTPServer(ThreadingHTTPServer):
    """Prevent Windows SO_REUSEADDR from silently binding a second server behind a stale instance."""
    allow_reuse_address = False

    def server_bind(self):
        if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            except OSError:
                pass
        super().server_bind()


def main():
    try:
        server = ExclusiveThreadingHTTPServer((HOST, PORT), StudioHandler)
    except OSError as exc:
        print(f"Cannot start Studio on {HOST}:{PORT}: {exc}")
        print("Another process may be using the port. Set STUDIO_PORT to a different value.")
        return
    url = f"http://{HOST}:{PORT}"
    print("=" * 60)
    print(f"  Haylou Watch 4S Studio running at {url}")
    print("  Press Ctrl+C to stop. Logs: set STUDIO_LOG=1")
    print("=" * 60)
    if not os.environ.get("STUDIO_NO_BROWSER") and not os.environ.get("STUDIO_NO_OPEN"):
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Studio…")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
