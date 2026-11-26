"""
Haylou Watch 4S (LS26) — Unified Multi-Layer Watchface Compiler & Renderer

Hardware-verified byte-for-byte against official Haylou Watch 4S (LS26001) cloud dials.
Compiles any combination of Z-ordered layers:
  - Background: Custom Image, Solid/Gradient, Ben 10 Omnitrix, or Animated GIF/WebP (`01 2e`)
  - Tap-to-Switch Multi-Scene / Theme Art (`01 1a`, 2-6 interactive scenes cycled on tap)
  - Procedural Tick / Bezel Generator (`01 00`: minimal dots, baton, diver, roman, arabic, tachymeter, neon, radar HUD)
  - Multi-Zone Animated Sprites (`01 2e`, 1-3 independent GIF/WebP loops at any Z-order)
  - Multiple Simultaneous Progress Gauges (`01 12`: Battery/Steps/Calories/Distance/Active rings, arcs, bars, icons)
    + Native Dynamic Battery Fill Bar (`01 05`)
  - Custom PNG Overlay / Sticker Layers (`01 00`) & Custom Text Labels (`01 00`)
  - Live Weather Icon (`01 1b`, 9 states) + Live Temperature (`01 1c`, `-` / `°C` / `°F`)
  - Bluetooth Connection Status Indicator (`01 14`, disconnected/connected 2-state badge)
  - Digital Clock (`01 02`, blinking colon) + Live Seconds (`01 18`) + AM/PM Indicator (`01 11`)
  - Live Date (`01 0f` Month MM, `01 0d` Day DD, `01 0e` Month Name JAN..DEC, `01 10` 4-Digit Year YYYY)
  - Live Weekday (`01 04`, 7-frame SUN..SAT)
  - Live Health Telemetry: Steps (`01 07`), Heart Rate (`01 23` + `01 06`), Calories (`01 09`),
    Distance (`01 08` + dynamic `01 1f` km/mi unit), Battery % (`01 15`)
  - Analog Hands (`01 0a`, 7 procedural styles + Custom PNG hand uploads)
into a native Watch 4S ARGB565-RLE `.bin` file with multiple independent digit font tables (`DT#0..DT#N`).
"""

from __future__ import annotations

import math
import os
import struct
import sys
from PIL import Image, ImageDraw, ImageFilter, ImageFont, ImageSequence

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from watchface_bin_maker import (
    encode_image_rle_argb565,
    pad4_ff,
    prepare_circular_image,
    WATCH_W,
    WATCH_H,
    PREV_W,
    PREV_H,
)
from omnitrix_watchface_maker import (
    draw_omnitrix_bg,
    draw_omnitrix_hands,
    hex_to_rgb,
    palette_from_hex,
    resolve_palette,
)

W, H = WATCH_W, WATCH_H
CX, CY = W // 2, H // 2
MAX_WATCH_BIN_BYTES = 1_300_000  # Official Watch 4S max cloud dial is ~1,289 KB

PROGRESS_METRIC_SUB = {
    "steps": 0x00,
    "calories": 0x02,
    "distance": 0x03,
    "active": 0x05,
    "battery": 0x06,
}

# Mandatory 8-byte resource table prefix emitted at 0x10 whenever 01 2e / 01 1a are used
ANIM_RESOURCE_PREFIX = bytes.fromhex("0002000000020100")

# Default back-to-front Z-order (Watch 4S draws layout opcodes back-to-front)
DEFAULT_LAYER_ORDER = [
    "background",
    "tap_switch",
    "bezel",
    "anim_sprites",
    "gauges",
    "overlays",
    "text_labels",
    "weather",
    "bluetooth",
    "weekday",
    "date",
    "clock",
    "telemetry",
    "hands",
]

# Hardware-verified 01 1b weather sprite order (decoded from official LS26 dials)
WEATHER_STATES = (
    "Partly Cloudy",  # 0
    "Fog / Mist",     # 1
    "Cloudy",         # 2
    "Rain",           # 3
    "Snow",           # 4
    "Sunny / Clear",  # 5
    "Wind / Dust",    # 6
    "Haze / Smog",    # 7
    "Unknown",        # 8
)

DEFAULT_DAY_NIGHT_THEMES = (
    {"label": "Midnight Cyber", "c1": "#060b18", "c2": "#132244"},
    {"label": "Solar Flare",    "c1": "#1a0a04", "c2": "#4d1d08"},
    {"label": "Emerald Matrix", "c1": "#04140a", "c2": "#0d3b1e"},
    {"label": "Crimson Dusk",   "c1": "#170512", "c2": "#3f0c2d"},
)

OMNITRIX_TAP_THEMES = {
    "green":         ("Active Green", "#39ff14"),
    "timeout":       ("Timeout Red", "#ff1818"),
    "self_destruct": ("Self-Destruct", "#ffa000"),
    "ben23":         ("Ben 23 Cyan", "#00e5ff"),
    "gwen":          ("Gwen 10 Pink", "#ff4fd8"),
    "mad":           ("Mad Ben Orange", "#ff7b00"),
    "nega":          ("Nega Silver", "#c8d6e5"),
    "albedo":        ("Albedo Crimson", "#e6194b"),
}


def load_font(font_path, size):
    if font_path and os.path.exists(font_path):
        try:
            return ImageFont.truetype(font_path, size)
        except Exception:
            pass
    for fallback in (
        r"C:\Windows\Fonts\arialbd.ttf",
        r"C:\Windows\Fonts\segoeuib.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/System/Library/Fonts/Helvetica.ttc",
    ):
        if os.path.exists(fallback):
            try:
                return ImageFont.truetype(fallback, size)
            except Exception:
                pass
    return ImageFont.load_default()


def _safe_hex_rgb(hex_str, default=(255, 255, 255)):
    try:
        return hex_to_rgb(hex_str)
    except Exception:
        return default


def render_styled_text_sprite(
    text,
    box_w,
    box_h,
    font,
    color="#FFFFFF",
    color2=None,
    stroke_width=0,
    stroke_color="#000000",
    glow_radius=0,
    glow_color=None,
):
    """Render a single glyph or label into a (box_w, box_h) RGBA sprite with gradient, outline, and glow."""
    canvas = Image.new("RGBA", (box_w, box_h), (0, 0, 0, 0))
    tmp = Image.new("RGBA", (box_w, box_h), (0, 0, 0, 0))
    td = ImageDraw.Draw(tmp)
    bbox = td.textbbox((0, 0), text, font=font, stroke_width=stroke_width)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    tx = (box_w - tw) // 2 - bbox[0]
    ty = (box_h - th) // 2 - bbox[1]

    c1 = _safe_hex_rgb(color)
    sc = _safe_hex_rgb(stroke_color, (0, 0, 0))

    if glow_radius > 0:
        gc = _safe_hex_rgb(glow_color or color, c1)
        glow_layer = Image.new("RGBA", (box_w, box_h), (0, 0, 0, 0))
        gd = ImageDraw.Draw(glow_layer)
        gd.text(
            (tx, ty),
            text,
            font=font,
            fill=(*gc, 255),
            stroke_width=max(1, stroke_width + 1),
            stroke_fill=(*gc, 255),
        )
        glow_layer = glow_layer.filter(ImageFilter.GaussianBlur(radius=glow_radius))
        canvas = Image.alpha_composite(canvas, glow_layer)

    if stroke_width > 0:
        stroke_layer = Image.new("RGBA", (box_w, box_h), (0, 0, 0, 0))
        sd = ImageDraw.Draw(stroke_layer)
        sd.text(
            (tx, ty),
            text,
            font=font,
            fill=(*sc, 255),
            stroke_width=stroke_width,
            stroke_fill=(*sc, 255),
        )
        canvas = Image.alpha_composite(canvas, stroke_layer)

    if color2 and color2.lower() != color.lower():
        c2 = _safe_hex_rgb(color2, c1)
        mask = Image.new("L", (box_w, box_h), 0)
        ImageDraw.Draw(mask).text((tx, ty), text, font=font, fill=255)
        grad = Image.new("RGBA", (box_w, box_h), (0, 0, 0, 0))
        gdraw = ImageDraw.Draw(grad)
        y_top = max(0, int(ty + bbox[1]))
        y_bot = min(box_h - 1, int(ty + bbox[3]))
        span = max(1, y_bot - y_top)
        for y in range(box_h):
            t = max(0.0, min(1.0, (y - y_top) / span))
            r = int(c1[0] + (c2[0] - c1[0]) * t)
            g = int(c1[1] + (c2[1] - c1[1]) * t)
            b = int(c1[2] + (c2[2] - c1[2]) * t)
            gdraw.line([(0, y), (box_w, y)], fill=(r, g, b, 255))
        fill_layer = Image.new("RGBA", (box_w, box_h), (0, 0, 0, 0))
        fill_layer.paste(grad, (0, 0), mask)
        canvas = Image.alpha_composite(canvas, fill_layer)
    else:
        fill_layer = Image.new("RGBA", (box_w, box_h), (0, 0, 0, 0))
        ImageDraw.Draw(fill_layer).text((tx, ty), text, font=font, fill=(*c1, 255))
        canvas = Image.alpha_composite(canvas, fill_layer)

    return canvas


def build_digit_sprites(
    font_path=None,
    font_size=28,
    color="#FFFFFF",
    color2=None,
    stroke_width=0,
    stroke_color="#000000",
    glow_radius=0,
    glow_color=None,
    min_box=(10, 14),
    max_box=(110, 130),
    pad_extra=4,
):
    """Render digits '0'..'9' into uniform RGBA sprites. Returns (digits_list, (dw, dh), font)."""
    font_size = max(12, min(96, int(font_size)))
    font = load_font(font_path, font_size)
    stroke_w = max(0, int(stroke_width))
    glow_r = max(0, int(glow_radius))
    pad_x = stroke_w * 2 + glow_r * 2 + max(1, pad_extra // 2)
    pad_y = stroke_w * 2 + glow_r * 2 + pad_extra

    tmp = ImageDraw.Draw(Image.new("RGBA", (10, 10)))
    max_w, max_h = min_box
    for d in range(10):
        bb = tmp.textbbox((0, 0), str(d), font=font, stroke_width=stroke_w)
        max_w = max(max_w, bb[2] - bb[0])
        max_h = max(max_h, bb[3] - bb[1])
    dw = min(max_box[0], max(min_box[0], int(max_w + pad_x)))
    dh = min(max_box[1], max(min_box[1], int(max_h + pad_y)))

    digits = [
        render_styled_text_sprite(
            str(d),
            dw,
            dh,
            font,
            color=color,
            color2=color2,
            stroke_width=stroke_w,
            stroke_color=stroke_color,
            glow_radius=glow_r,
            glow_color=glow_color,
        )
        for d in range(10)
    ]
    return digits, (dw, dh), font


def apply_amoled_dimmer(img_rgba, brightness_pct=100, vignette_pct=0):
    """Scale RGB pixel values for AMOLED dimming (15%..100%) and smooth radial dark edge vignette (0%..80%)."""
    b_scale = max(0.10, min(1.0, float(brightness_pct) / 100.0))
    v_strength = max(0.0, min(0.90, float(vignette_pct) / 100.0))
    if b_scale >= 0.999 and v_strength <= 0.001:
        return img_rgba

    w, h = img_rgba.size
    r, g, b, a = img_rgba.split()
    if b_scale < 0.999:
        lut = [int(i * b_scale) for i in range(256)]
        r = r.point(lut)
        g = g.point(lut)
        b = b.point(lut)
    out = Image.merge("RGBA", (r, g, b, a))

    if v_strength > 0.001:
        vig = Image.new("RGBA", (w, h), (0, 0, 0, 0))
        vd = ImageDraw.Draw(vig)
        cx, cy = w // 2, h // 2
        max_r = min(cx, cy)
        steps = 28
        for i in range(steps):
            t = i / (steps - 1)
            rad = int(max_r * (1.0 - 0.42 * (1.0 - t)))
            alpha = int(255 * v_strength * (t ** 1.8))
            vd.ellipse(
                (cx - rad, cy - rad, cx + rad, cy + rad),
                outline=(0, 0, 0, alpha),
                width=max(2, max_r // steps + 1),
            )
        vig_clipped = Image.new("RGBA", (w, h), (0, 0, 0, 0))
        vig_clipped.paste(vig, (0, 0), a)
        out = Image.alpha_composite(out, vig_clipped)
    return out


def _apply_opacity(img_rgba, opacity_pct=100):
    val = float(opacity_pct)
    op = val if 0.0 < val <= 1.0 else val / 100.0
    op = max(0.05, min(1.0, op))
    if op >= 0.999:
        return img_rgba
    r, g, b, a = img_rgba.split()
    a = a.point([int(v * op) for v in range(256)])
    return Image.merge("RGBA", (r, g, b, a))


def _prepare_circular_pil(frame_rgba, size, circular=True):
    """Center-crop and resize a PIL RGBA image to (size, size) with optional circular AMOLED mask."""
    img = frame_rgba.convert("RGBA")
    side = min(img.width, img.height)
    left = (img.width - side) // 2
    top = (img.height - side) // 2
    img = img.crop((left, top, left + side, top + side))
    img = img.resize((size, size), Image.Resampling.LANCZOS)
    if not circular:
        return img
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).ellipse((0, 0, size - 1, size - 1), fill=255)
    out = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    out.paste(img, (0, 0), mask)
    return out


def _posterize_for_rle(img_rgba, bits=5):
    """Lightly quantize RGB channels (preserving alpha) so busy multi-frame sprites RLE-compress tighter."""
    shift = 8 - bits
    mask = ((1 << bits) - 1) << shift
    r, g, b, a = img_rgba.split()
    lut = [i & mask for i in range(256)]
    return Image.merge("RGBA", (r.point(lut), g.point(lut), b.point(lut), a))


def is_animated_image_file(path):
    """Return True if the image file has more than 1 frame (GIF / animated WebP / APNG)."""
    if not path or not os.path.isfile(path):
        return False
    try:
        with Image.open(path) as im:
            return getattr(im, "n_frames", 1) > 1
    except Exception:
        return False


def extract_animated_frames(anim_cfg, override_count=None, posterize_bits=None):
    """
    Extract evenly-spaced RGBA frames from an animated GIF/WebP for Watch 4S `01 2e` playback.
    Supports both legacy background.anim_* keys and anim_sprites[] item keys.
    Returns (frames_list, (x, y, w, h), hardware_interval, frame_duration_ms).
    """
    img_path = anim_cfg.get("image_path")
    if not img_path or not os.path.isfile(img_path):
        return [], (0, 0, W, H), 15, 250

    max_frames = max(2, min(20, int(override_count or anim_cfg.get("frames", anim_cfg.get("anim_frames", 8)))))
    fps = max(1.0, min(15.0, float(anim_cfg.get("fps", anim_cfg.get("anim_fps", 4)))))
    anim_size = max(80, min(W, int(anim_cfg.get("size", anim_cfg.get("anim_size", W)))))
    anim_size = anim_size & ~1
    circular = bool(anim_cfg.get("circular", anim_cfg.get("anim_circular", True)))
    brightness = float(anim_cfg.get("brightness", 100))
    vignette = float(anim_cfg.get("vignette", 0)) if anim_size >= W else 0.0

    cx = int(anim_cfg.get("x", anim_cfg.get("anim_x", CX)))
    cy = int(anim_cfg.get("y", anim_cfg.get("anim_y", CY)))
    ax = max(0, min(W - anim_size, cx - anim_size // 2))
    ay = max(0, min(H - anim_size, cy - anim_size // 2))

    raw_frames = []
    with Image.open(img_path) as im:
        n = getattr(im, "n_frames", 1)
        if n <= 1:
            raw_frames = [im.convert("RGBA")]
        else:
            count = min(n, max_frames)
            indices = sorted(set(int(round(i * (n - 1) / max(1, count - 1))) for i in range(count)))
            idx_set = set(indices)
            for idx, frame in enumerate(ImageSequence.Iterator(im)):
                if idx in idx_set:
                    raw_frames.append(frame.convert("RGBA"))

    processed = []
    for fr in raw_frames:
        sq = _prepare_circular_pil(fr, anim_size, circular=circular)
        sq = apply_amoled_dimmer(sq, brightness, vignette)
        if posterize_bits:
            sq = _posterize_for_rle(sq, bits=posterize_bits)
        processed.append(sq)

    hw_interval = max(4, min(60, int(round(60.0 / fps))))
    preview_ms = max(65, int(round(1000.0 / fps)))
    return processed, (ax, ay, anim_size, anim_size), hw_interval, preview_ms


def _build_solid_gradient_bg(bg_cfg, size=W, circular=True):
    brightness = float(bg_cfg.get("brightness", 100))
    vignette = float(bg_cfg.get("vignette", 0))
    c1 = _safe_hex_rgb(bg_cfg.get("color", "#0b0e14"), (11, 14, 20))
    c2 = _safe_hex_rgb(bg_cfg.get("color2", bg_cfg.get("color", "#0b0e14")), c1)
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    for y in range(size):
        t = y / max(1, size - 1)
        r = int(c1[0] + (c2[0] - c1[0]) * t)
        g = int(c1[1] + (c2[1] - c1[1]) * t)
        b = int(c1[2] + (c2[2] - c1[2]) * t)
        d.line([(0, y), (size, y)], fill=(r, g, b, 255))
    if circular:
        mask = Image.new("L", (size, size), 0)
        ImageDraw.Draw(mask).ellipse((0, 0, size - 1, size - 1), fill=255)
        out = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        out.paste(img, (0, 0), mask)
    else:
        out = img
    return apply_amoled_dimmer(out, brightness, vignette)


def build_background(bg_cfg):
    mode = bg_cfg.get("mode", "solid")
    brightness = float(bg_cfg.get("brightness", 100))
    vignette = float(bg_cfg.get("vignette", 0))
    if mode == "animated_gif":
        anim_size = int(bg_cfg.get("anim_size", W))
        base = _build_solid_gradient_bg(bg_cfg)
        frames, (ax, ay, _, _), _, _ = extract_animated_frames(bg_cfg, override_count=2)
        if frames:
            if anim_size >= W:
                return frames[0]
            base.paste(frames[0], (ax, ay), frames[0])
        return base
    if mode == "image" and bg_cfg.get("image_path") and os.path.exists(bg_cfg["image_path"]):
        img = prepare_circular_image(bg_cfg["image_path"], W)
        return apply_amoled_dimmer(img, brightness, vignette)
    if mode == "omnitrix":
        style = bg_cfg.get("omni_style", "alien_force")
        colorway = bg_cfg.get("omni_colorway", "green")
        custom_hex = bg_cfg.get("omni_hex") or None
        ticks = bool(bg_cfg.get("omni_ticks", True))
        glow = float(bg_cfg.get("omni_glow", 1.0))
        pal = resolve_palette(colorway, custom_hex)
        if style not in ("alien_force", "os", "omniverse", "5yl"):
            style = "alien_force"
        img = draw_omnitrix_bg(style=style, palette=pal, show_ticks=ticks, glow_strength=glow)
        return apply_amoled_dimmer(img, brightness, vignette)
    return _build_solid_gradient_bg(bg_cfg)


# --------------------------------------------------------------------------- #
# Tap-to-Switch Multi-Scene / Theme Art (Opcode 01 1a)
# --------------------------------------------------------------------------- #

def build_tap_switch_assets(ts_cfg, posterize_bits=None):
    """
    Build 2..6 interactive tap-to-switch scene frames for Watch 4S opcode `01 1a`.
    Returns (x, y, frames_list) or (0, 0, []) if disabled/insufficient frames.
    """
    if not ts_cfg or not ts_cfg.get("enabled"):
        return 0, 0, []

    mode = ts_cfg.get("mode", "day_night")
    size = max(120, min(W, int(ts_cfg.get("size", W)))) & ~1
    circular = bool(ts_cfg.get("circular", True))
    brightness = float(ts_cfg.get("brightness", 100))
    opacity = float(ts_cfg.get("opacity", 100))
    count_cap = max(2, min(6, int(ts_cfg.get("count", 6))))
    vignette = float(ts_cfg.get("vignette", 0)) if size >= W else 0.0
    cx = int(ts_cfg.get("x", CX))
    cy = int(ts_cfg.get("y", CY))
    tx = max(0, min(W - size, cx - size // 2))
    ty = max(0, min(H - size, cy - size // 2))

    frames = []
    if mode == "custom_images":
        for item in (ts_cfg.get("frames") or [])[:count_cap]:
            if not isinstance(item, dict):
                continue
            p = item.get("image_path")
            if p and os.path.isfile(p):
                try:
                    with Image.open(p) as im:
                        fr = _prepare_circular_pil(im.convert("RGBA"), size, circular=circular)
                        fr = apply_amoled_dimmer(fr, brightness, vignette)
                        frames.append(_apply_opacity(fr, opacity))
                except Exception:
                    pass
    elif mode == "omnitrix_themes":
        style = ts_cfg.get("omni_style", "alien_force")
        if style not in ("alien_force", "os", "omniverse", "5yl"):
            style = "alien_force"
        ticks = bool(ts_cfg.get("omni_ticks", True))
        glow = float(ts_cfg.get("omni_glow", 1.0))
        theme_keys = ts_cfg.get("omni_themes") or ["green", "timeout", "ben23", "gwen", "self_destruct", "mad"]
        for key in theme_keys[:count_cap]:
            _, hex_col = OMNITRIX_TAP_THEMES.get(key, ("Active Green", "#39ff14"))
            pal = resolve_palette(key, hex_col)
            img = draw_omnitrix_bg(style=style, palette=pal, show_ticks=ticks, glow_strength=glow)
            if size < W:
                img = _prepare_circular_pil(img, size, circular=circular)
            frames.append(_apply_opacity(apply_amoled_dimmer(img, brightness, vignette), opacity))
    else:  # "day_night" multi-theme gradient scenes
        themes = ts_cfg.get("themes") or ts_cfg.get("theme_colors") or list(DEFAULT_DAY_NIGHT_THEMES)
        for th in themes[:count_cap]:
            if not isinstance(th, dict):
                continue
            fr = _build_solid_gradient_bg(
                {"color": th.get("c1", "#060b18"), "color2": th.get("c2", "#132244"),
                 "brightness": brightness, "vignette": vignette},
                size=size,
                circular=circular,
            )
            # Add subtle radial highlight ring so each theme looks distinct and machined
            accent = _safe_hex_rgb(th.get("c2", "#38bdf8"))
            d = ImageDraw.Draw(fr)
            d.ellipse((6, 6, size - 7, size - 7), outline=(*accent, 110), width=2)
            frames.append(_apply_opacity(fr, opacity))

    if len(frames) < 2:
        return 0, 0, []
    if posterize_bits:
        frames = [_posterize_for_rle(f, bits=posterize_bits) for f in frames]
    return tx, ty, frames


# --------------------------------------------------------------------------- #
# Procedural Tick / Bezel Generator (Opcode 01 00)
# --------------------------------------------------------------------------- #

def build_bezel_layer(bezel_cfg):
    """Render a 2x-supersampled transparent 466x466 watch bezel / index tick ring."""
    if not bezel_cfg or not bezel_cfg.get("enabled"):
        return None
    style = bezel_cfg.get("style", "baton_classic")
    prim = _safe_hex_rgb(bezel_cfg.get("color", "#e2e8f0"))
    accent = _safe_hex_rgb(bezel_cfg.get("accent_color", "#38bdf8"))
    opacity = float(bezel_cfg.get("opacity", 95))
    inset = max(0, min(48, int(bezel_cfg.get("radius_inset", bezel_cfg.get("inset", 8)))))
    show_min = bool(bezel_cfg.get("show_minute_ticks", True))
    glow = max(0, min(8, int(bezel_cfg.get("glow", 0))))
    font_path = bezel_cfg.get("font_path")

    S = 2
    img = Image.new("RGBA", (W * S, H * S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    cx, cy = CX * S, CY * S
    r_out = (228 - inset) * S

    def pt(deg, rad):
        a = math.radians(deg - 90)
        return (cx + math.cos(a) * rad, cy + math.sin(a) * rad)

    def draw_centered_text(text, deg, rad, font_sz, col_rgba):
        fnt = load_font(font_path, font_sz * S)
        tx, ty = pt(deg, rad)
        bb = d.textbbox((0, 0), text, font=fnt)
        tw, th = bb[2] - bb[0], bb[3] - bb[1]
        d.text((tx - tw / 2 - bb[0], ty - th / 2 - bb[1]), text, font=fnt, fill=col_rgba)

    if show_min and style in ("minimal_dots", "baton_classic", "diver_indices", "roman_numerals", "arabic_numbers"):
        for i in range(60):
            if i % 5 == 0:
                continue
            p1 = pt(i * 6, r_out - 9 * S)
            p2 = pt(i * 6, r_out - 2 * S)
            d.line([p1, p2], fill=(*prim, 120), width=max(1, int(1.5 * S)))

    if style == "minimal_dots":
        for h in range(12):
            deg = h * 30
            is_card = (h % 3 == 0)
            rad_dot = (6 if is_card else 3.5) * S
            col = (*accent, 255) if is_card else (*prim, 220)
            px, py = pt(deg, r_out - 12 * S)
            d.ellipse((px - rad_dot, py - rad_dot, px + rad_dot, py + rad_dot), fill=col)

    elif style == "baton_classic":
        d.ellipse((cx - r_out, cy - r_out, cx + r_out, cy + r_out), outline=(*prim, 75), width=1 * S)
        for h in range(12):
            deg = h * 30
            is_card = (h % 3 == 0)
            col = (*accent, 255) if h == 0 else (*prim, 240)
            if h == 0:
                # Luxury double baton at 12 o'clock
                for off_deg in (-2.0, 2.0):
                    p1 = pt(off_deg, r_out - 26 * S)
                    p2 = pt(off_deg, r_out - 4 * S)
                    d.line([p1, p2], fill=col, width=4 * S)
            else:
                p1 = pt(deg, r_out - (24 if is_card else 18) * S)
                p2 = pt(deg, r_out - 4 * S)
                d.line([p1, p2], fill=col, width=(5 if is_card else 3) * S)

    elif style == "diver_indices":
        d.ellipse((cx - r_out, cy - r_out, cx + r_out, cy + r_out), outline=(*prim, 140), width=2 * S)
        r_mid = r_out - 18 * S
        for h in range(12):
            deg = h * 30
            if h == 0:
                # Iconic inverted triangle at 12
                tip = pt(0, r_out - 30 * S)
                l_pt = pt(-4.2, r_out - 6 * S)
                r_pt = pt(4.2, r_out - 6 * S)
                d.polygon([tip, l_pt, r_pt], fill=(*accent, 255), outline=(10, 12, 16, 220))
            elif h in (3, 6, 9):
                p1 = pt(deg, r_out - 28 * S)
                p2 = pt(deg, r_out - 6 * S)
                d.line([p1, p2], fill=(*prim, 255), width=8 * S)
                d.line([p1, p2], fill=(*accent, 200), width=3 * S)
            else:
                px, py = pt(deg, r_mid)
                rr = 8 * S
                d.ellipse((px - rr, py - rr, px + rr, py + rr), fill=(*prim, 245), outline=(15, 20, 25, 220), width=2 * S)

    elif style == "roman_numerals":
        romans = ["XII", "I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X", "XI"]
        d.ellipse((cx - r_out, cy - r_out, cx + r_out, cy + r_out), outline=(*prim, 130), width=2 * S)
        d.ellipse((cx - (r_out - 10 * S), cy - (r_out - 10 * S), cx + (r_out - 10 * S), cy + (r_out - 10 * S)), outline=(*prim, 85), width=1 * S)
        for h, label in enumerate(romans):
            col = (*accent, 255) if (h % 3 == 0) else (*prim, 235)
            draw_centered_text(label, h * 30, r_out - 28 * S, 18 if h % 3 == 0 else 15, col)

    elif style == "arabic_numbers":
        d.ellipse((cx - r_out, cy - r_out, cx + r_out, cy + r_out), outline=(*prim, 100), width=1 * S)
        for h in range(12):
            num = "12" if h == 0 else str(h)
            is_card = (h % 3 == 0)
            col = (*accent, 255) if is_card else (*prim, 230)
            draw_centered_text(num, h * 30, r_out - 26 * S, 21 if is_card else 16, col)
            p1 = pt(h * 30, r_out - 10 * S)
            p2 = pt(h * 30, r_out - 2 * S)
            d.line([p1, p2], fill=col, width=3 * S)

    elif style == "tachymeter":
        # Motorsport bezel with tachymeter speed markings & redline accent arc
        r_in = r_out - 28 * S
        d.ellipse((cx - r_out, cy - r_out, cx + r_out, cy + r_out), outline=(*prim, 170), width=2 * S)
        d.ellipse((cx - r_in, cy - r_in, cx + r_in, cy + r_in), outline=(*prim, 110), width=1 * S)
        d.arc((cx - r_out + 4 * S, cy - r_out + 4 * S, cx + r_out - 4 * S, cy + r_out - 4 * S),
              start=-90, end=-30, fill=(*accent, 230), width=4 * S)
        tachy_marks = [
            (0, "60"), (30, "500"), (45, "400"), (60, "300"), (75, "240"), (90, "200"),
            (105, "180"), (120, "150"), (150, "120"), (180, "100"), (210, "90"),
            (240, "80"), (270, "75"), (300, "70"), (330, "65"),
        ]
        for deg, txt in tachy_marks:
            p1 = pt(deg, r_out - 6 * S)
            p2 = pt(deg, r_out)
            col_c = accent if deg <= 60 else prim
            d.line([p1, p2], fill=(*col_c, 240), width=2 * S)
            draw_centered_text(txt, deg, r_out - 16 * S, 11, (*col_c, 235))
        if show_min:
            for i in range(60):
                p1 = pt(i * 6, r_in - 6 * S)
                p2 = pt(i * 6, r_in)
                d.line([p1, p2], fill=(*prim, 180 if i % 5 == 0 else 95), width=(3 if i % 5 == 0 else 1) * S)

    elif style == "neon_rings":
        for off_r, col_c, w_px in ((0, accent, 3), (12, prim, 2), (24, accent, 1)):
            rr = r_out - off_r * S
            d.ellipse((cx - rr, cy - rr, cx + rr, cy + rr), outline=(*col_c, 220 - off_r * 4), width=w_px * S)
        for h in range(12):
            p1 = pt(h * 30, r_out - 24 * S)
            p2 = pt(h * 30, r_out - 2 * S)
            col_h = accent if h % 3 == 0 else prim
            d.line([p1, p2], fill=(*col_h, 240), width=(4 if h % 3 == 0 else 2) * S)

    elif style == "radar_hud":
        # Tactical compass HUD ring with degree ticks & cardinal azimuth labels
        for start_deg in (-80, 10, 100, 190):
            d.arc((cx - r_out, cy - r_out, cx + r_out, cy + r_out),
                  start=start_deg, end=start_deg + 70, fill=(*accent, 210), width=3 * S)
        r_in = r_out - 22 * S
        d.ellipse((cx - r_in, cy - r_in, cx + r_in, cy + r_in), outline=(*prim, 100), width=1 * S)
        for i in range(72):
            deg = i * 5
            is_maj = (deg % 30 == 0)
            p1 = pt(deg, r_out - (16 if is_maj else 9) * S)
            p2 = pt(deg, r_out - 3 * S)
            col_d = accent if deg % 90 == 0 else prim
            d.line([p1, p2], fill=(*col_d, 230 if is_maj else 110), width=(3 if is_maj else 1) * S)
        for deg, lbl in ((0, "000"), (90, "090"), (180, "180"), (270, "270")):
            draw_centered_text(lbl, deg, r_out - 30 * S, 12, (*accent, 245))

    if glow > 0:
        g_layer = img.filter(ImageFilter.GaussianBlur(radius=glow * S))
        img = Image.alpha_composite(g_layer, img)

    img = img.resize((W, H), Image.Resampling.LANCZOS)
    return _apply_opacity(img, opacity)


# --------------------------------------------------------------------------- #
# Live Weather Icon (01 1b) + Temperature (01 1c)
# --------------------------------------------------------------------------- #

def _draw_weather_icon(state_idx, size, style="color", tint_rgb=(255, 255, 255)):
    """
    Draw one crisp 3x-supersampled weather icon for Watch 4S `01 1b` state 0..8:
      0=Partly Cloudy, 1=Fog, 2=Cloudy, 3=Rain, 4=Snow, 5=Sunny, 6=Wind/Dust, 7=Haze, 8=Unknown
    """
    s = max(20, min(72, int(size)))
    S = 3
    w = h = s * S
    im = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)

    if style == "color":
        sun_c = (255, 198, 64, 255)
        cloud_c = (242, 246, 252, 255)
        cloud_hi = (205, 218, 234, 255)
        rain_c = (56, 189, 248, 255)
        snow_c = (186, 230, 253, 255)
        fog_c = (148, 163, 184, 235)
        wind_c = (226, 232, 240, 245)
    else:
        sun_c = (*tint_rgb, 255)
        cloud_c = (*tint_rgb, 245)
        cloud_hi = (*tint_rgb, 180)
        rain_c = (*tint_rgb, 255)
        snow_c = (*tint_rgb, 255)
        fog_c = (*tint_rgb, 195)
        wind_c = (*tint_rgb, 245)

    def draw_sun(cx_f, cy_f, r_f, rays=8):
        cx, cy, r = w * cx_f, h * cy_f, w * r_f
        for i in range(rays):
            ang = math.radians(i * (360 / rays))
            p1 = (cx + math.cos(ang) * (r * 1.28), cy + math.sin(ang) * (r * 1.28))
            p2 = (cx + math.cos(ang) * (r * 1.72), cy + math.sin(ang) * (r * 1.72))
            d.line([p1, p2], fill=sun_c, width=max(2, int(w * 0.065)))
        d.ellipse((cx - r, cy - r, cx + r, cy + r), fill=sun_c)

    def draw_cloud(y_off=0.0, scale=1.0, col=cloud_c):
        # Soft puffy 3-lobe cloud + rounded base
        x0 = w * (0.12 + (1 - scale) * 0.35)
        y0 = h * (0.34 + y_off)
        cw = w * 0.76 * scale
        ch = h * 0.42 * scale
        d.ellipse((x0 + cw * 0.02, y0 + ch * 0.22, x0 + cw * 0.46, y0 + ch * 1.0), fill=col)
        d.ellipse((x0 + cw * 0.22, y0 - ch * 0.14, x0 + cw * 0.72, y0 + ch * 0.80), fill=col)
        d.ellipse((x0 + cw * 0.52, y0 + ch * 0.14, x0 + cw * 0.98, y0 + ch * 1.0), fill=col)
        d.rounded_rectangle((x0 + cw * 0.16, y0 + ch * 0.54, x0 + cw * 0.84, y0 + ch * 1.0), radius=int(ch * 0.22), fill=col)

    if state_idx == 0:  # Partly Cloudy
        draw_sun(0.64, 0.34, 0.18, rays=8)
        draw_cloud(y_off=0.14, scale=0.95)
    elif state_idx == 1:  # Fog / Mist
        draw_cloud(y_off=-0.06, scale=0.92)
        for row_y, x1, x2 in ((0.76, 0.18, 0.82), (0.88, 0.26, 0.74)):
            d.line([(w * x1, h * row_y), (w * x2, h * row_y)], fill=fog_c, width=max(2, int(w * 0.065)))
    elif state_idx == 2:  # Cloudy
        draw_cloud(y_off=-0.02, scale=0.78, col=cloud_hi)
        draw_cloud(y_off=0.12, scale=0.95, col=cloud_c)
    elif state_idx == 3:  # Rain
        draw_cloud(y_off=-0.10, scale=0.92)
        for rx, ry1, ry2 in ((0.30, 0.72, 0.90), (0.50, 0.68, 0.92), (0.70, 0.72, 0.90)):
            d.line([(w * rx, h * ry1), (w * (rx - 0.05), h * ry2)], fill=rain_c, width=max(2, int(w * 0.07)))
    elif state_idx == 4:  # Snow
        draw_cloud(y_off=-0.10, scale=0.92)
        for sx, sy in ((0.34, 0.81), (0.64, 0.81)):
            cx, cy = w * sx, h * sy
            rr = w * 0.095
            for deg in (0, 60, 120):
                a = math.radians(deg)
                d.line([(cx - math.cos(a) * rr, cy - math.sin(a) * rr),
                        (cx + math.cos(a) * rr, cy + math.sin(a) * rr)], fill=snow_c, width=max(2, int(w * 0.045)))
    elif state_idx == 5:  # Sunny / Clear
        draw_sun(0.50, 0.50, 0.24, rays=8)
    elif state_idx == 6:  # Wind / Dust
        lw = max(2, int(w * 0.065))
        d.line([(w * 0.12, h * 0.38), (w * 0.68, h * 0.38)], fill=wind_c, width=lw)
        d.arc((w * 0.54, h * 0.16, w * 0.80, h * 0.38), start=-90, end=100, fill=wind_c, width=lw)
        d.line([(w * 0.16, h * 0.58), (w * 0.80, h * 0.58)], fill=wind_c, width=lw)
        d.arc((w * 0.64, h * 0.58, w * 0.88, h * 0.82), start=-90, end=120, fill=wind_c, width=lw)
        for dx, dy in ((0.28, 0.24), (0.80, 0.22), (0.34, 0.78)):
            r = w * 0.055
            d.ellipse((w * dx - r, h * dy - r, w * dx + r, h * dy + r), fill=rain_c)
    elif state_idx == 7:  # Haze / Smog
        lw = max(2, int(w * 0.065))
        for ry in (0.34, 0.52, 0.70):
            d.line([(w * 0.14, h * ry), (w * 0.86, h * ry)], fill=fog_c, width=lw)
        for dx in (0.24, 0.50, 0.76):
            r = w * 0.048
            d.ellipse((w * dx - r, h * 0.18 - r, w * dx + r, h * 0.18 + r), fill=rain_c)
            d.ellipse((w * dx - r, h * 0.85 - r, w * dx + r, h * 0.85 + r), fill=rain_c)
    else:  # 8: Unknown
        draw_cloud(y_off=0.04, scale=0.95)
        fnt = load_font(None, int(h * 0.34))
        bb = d.textbbox((0, 0), "?", font=fnt)
        tw, th = bb[2] - bb[0], bb[3] - bb[1]
        d.text((w * 0.50 - tw / 2 - bb[0], h * 0.54 - th / 2 - bb[1]), "?", font=fnt, fill=(24, 30, 38, 255))

    if style == "neon":
        glow = im.filter(ImageFilter.GaussianBlur(radius=3 * S))
        im = Image.alpha_composite(glow, im)

    return im.resize((s, s), Image.Resampling.LANCZOS)


def build_weather_assets(w_cfg):
    """Build 9 weather sprites (01 1b) and/or temperature digit table + (-, °C, °F) glyphs (01 1c)."""
    if not w_cfg or not w_cfg.get("enabled"):
        return None
    show_icon = bool(w_cfg.get("show_icon", True))
    show_temp = bool(w_cfg.get("show_temp", True))
    if not show_icon and not show_temp:
        return None

    icon_data = None
    if show_icon:
        isz = max(20, min(68, int(w_cfg.get("icon_size", 36))))
        istyle = w_cfg.get("icon_style", "color")
        tint = _safe_hex_rgb(w_cfg.get("icon_color", "#38bdf8"))
        frames = [_draw_weather_icon(i, isz, style=istyle, tint_rgb=tint) for i in range(9)]
        ix = max(0, min(W - isz, int(w_cfg.get("icon_x", 180)) - isz // 2))
        iy = max(0, min(H - isz, int(w_cfg.get("icon_y", 110)) - isz // 2))
        raw_ps = w_cfg.get("preview_state", 5)
        if isinstance(raw_ps, str) and not raw_ps.strip().isdigit():
            slug = raw_ps.strip().lower().replace("_", " ").replace("-", " ")
            ps_idx = 5
            for idx_s, label_s in enumerate(WEATHER_STATES):
                if slug in label_s.lower() or label_s.lower().startswith(slug):
                    ps_idx = idx_s
                    break
        else:
            ps_idx = max(0, min(8, int(raw_ps)))
        icon_data = {
            "x": ix,
            "y": iy,
            "w": isz,
            "h": isz,
            "frames": frames,
            "preview_state": ps_idx,
        }

    temp_data = None
    if show_temp:
        fsize = max(14, min(48, int(w_cfg.get("font_size", 24))))
        col = w_cfg.get("color", "#f8fafc")
        sw = max(0, int(w_cfg.get("stroke_width", 1)))
        scol = w_cfg.get("stroke_color", "#000000")
        digits, (dw, dh), font = build_digit_sprites(
            font_path=w_cfg.get("font_path"),
            font_size=fsize,
            color=col,
            stroke_width=sw,
            stroke_color=scol,
            min_box=(10, 14),
            max_box=(48, 60),
            pad_extra=3,
        )
        minus_w = max(8, int(dw * 0.65))
        unit_w = max(16, int(dw * 1.45))
        minus_sp = render_styled_text_sprite("-", minus_w, dh, font, color=col, stroke_width=sw, stroke_color=scol)
        degc_sp = render_styled_text_sprite("°C", unit_w, dh, font, color=col, stroke_width=sw, stroke_color=scol)
        degf_sp = render_styled_text_sprite("°F", unit_w, dh, font, color=col, stroke_width=sw, stroke_color=scol)
        raw_align = w_cfg.get("align", 2)
        align_map = {"left": 0, "right": 1, "center": 2}
        align = align_map.get(str(raw_align).strip().lower(), int(raw_align) if str(raw_align).strip().isdigit() else 2)
        if align not in (0, 1, 2):
            align = 2
        tx = max(0, min(W - 1, int(w_cfg.get("temp_x", 246))))
        ty = max(0, min(H - dh, int(w_cfg.get("temp_y", 110)) - dh // 2))
        temp_data = {
            "digits": digits,
            "wh": (dw, dh),
            "minus": minus_sp,
            "degc": degc_sp,
            "degf": degf_sp,
            "x": tx,
            "y": ty,
            "align": align,
            "unit_preview": "F" if str(w_cfg.get("unit_preview", "C")).upper() == "F" else "C",
        }

    return {"icon": icon_data, "temp": temp_data}


# --------------------------------------------------------------------------- #
# Bluetooth Status Indicator (Opcode 01 14)
# --------------------------------------------------------------------------- #

def _draw_bt_sprite(connected, size, style, col_rgb):
    s = max(16, min(60, int(size)))
    S = 3
    w = h = s * S
    im = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    alpha = 255 if connected else 175
    col = (*col_rgb, alpha)

    def draw_rune(scale=1.0, c=col):
        cx, cy = w * 0.5, h * 0.5
        rx, ry = w * 0.22 * scale, h * 0.34 * scale
        lw = max(2, int(w * 0.075 * scale))
        pts = [
            (cx - rx * 0.8, cy - ry * 0.45),
            (cx + rx * 0.85, cy + ry * 0.48),
            (cx, cy + ry),
            (cx, cy - ry),
            (cx + rx * 0.85, cy - ry * 0.48),
            (cx - rx * 0.8, cy + ry * 0.45),
        ]
        d.line(pts, fill=c, width=lw, joint="curve")

    if style == "pill_badge":
        bg_a = 72 if connected else 42
        d.ellipse((2 * S, 2 * S, w - 2 * S, h - 2 * S), fill=(*col_rgb, bg_a), outline=col, width=max(2, int(w * 0.06)))
        draw_rune(scale=0.72)
    elif style == "link_chain":
        lw = max(2, int(w * 0.09))
        d.arc((w * 0.14, h * 0.26, w * 0.56, h * 0.74), start=90, end=270, fill=col, width=lw)
        d.arc((w * 0.44, h * 0.26, w * 0.86, h * 0.74), start=-90, end=90, fill=col, width=lw)
        if connected:
            d.line([(w * 0.34, h * 0.50), (w * 0.66, h * 0.50)], fill=col, width=lw)
        else:
            d.line([(w * 0.22, h * 0.78), (w * 0.78, h * 0.22)], fill=col, width=lw)
    elif style == "dot_ring":
        d.ellipse((w * 0.14, h * 0.14, w * 0.86, h * 0.86), outline=col, width=max(2, int(w * 0.08)))
        if connected:
            d.ellipse((w * 0.32, h * 0.32, w * 0.68, h * 0.68), fill=col)
    else:  # "bt_rune"
        draw_rune(scale=0.95)
        if not connected:
            d.line([(w * 0.16, h * 0.82), (w * 0.84, h * 0.18)], fill=col, width=max(2, int(w * 0.075)))

    if connected and style in ("pill_badge", "dot_ring"):
        glow = im.filter(ImageFilter.GaussianBlur(radius=2 * S))
        im = Image.alpha_composite(glow, im)
    return im.resize((s, s), Image.Resampling.LANCZOS)


def build_bluetooth_assets(bt_cfg):
    """Build 2-state Bluetooth sprites (01 14). Hardware order: s0=disconnected, s1=connected."""
    if not bt_cfg or not bt_cfg.get("enabled"):
        return None
    size = max(16, min(56, int(bt_cfg.get("size", 26))))
    style = bt_cfg.get("style", "bt_rune")
    conn_rgb = _safe_hex_rgb(bt_cfg.get("connected_color", "#38bdf8"))
    disc_rgb = _safe_hex_rgb(bt_cfg.get("disconnected_color", "#ff453a"))
    sp_disc = _draw_bt_sprite(False, size, style, disc_rgb)
    sp_conn = _draw_bt_sprite(True, size, style, conn_rgb)
    bx = max(0, min(W - size, int(bt_cfg.get("x", 233)) - size // 2))
    by = max(0, min(H - size, int(bt_cfg.get("y", 42)) - size // 2))
    return {
        "x": bx,
        "y": by,
        "w": size,
        "h": size,
        "disconnected": sp_disc,
        "connected": sp_conn,
        "preview_connected": bool(bt_cfg.get("preview_connected", True)),
    }


# --------------------------------------------------------------------------- #
# Digital Clock (01 02) + Live Seconds (01 18) + AM/PM (01 11)
# --------------------------------------------------------------------------- #

def build_digital_clock_assets(clk_cfg):
    font_size = max(24, min(96, int(clk_cfg.get("font_size", 60))))
    stroke_w = int(clk_cfg.get("stroke_width", 0))
    glow_r = int(clk_cfg.get("glow_radius", 0))

    digits, (dw, dh), font = build_digit_sprites(
        font_path=clk_cfg.get("font_path"),
        font_size=font_size,
        color=clk_cfg.get("color", "#FFFFFF"),
        color2=clk_cfg.get("color2") or None,
        stroke_width=stroke_w,
        stroke_color=clk_cfg.get("stroke_color", "#000000"),
        glow_radius=glow_r,
        glow_color=clk_cfg.get("glow_color") or None,
        min_box=(24, 34),
        max_box=(110, 130),
        pad_extra=8,
    )

    cx = int(clk_cfg.get("x", 233))
    cy = int(clk_cfg.get("y", 233))
    layout = clk_cfg.get("layout", "horizontal")
    gap = int(clk_cfg.get("spacing", 6))
    show_colon = bool(clk_cfg.get("show_colon", layout == "horizontal"))

    colon_info = None
    if layout == "stacked":
        row_gap = max(4, gap)
        x_left = cx - dw - gap // 2
        x_right = cx + gap // 2
        y_top = cy - dh - row_gap // 2
        y_bot = cy + row_gap // 2
        coords = [(x_left, y_top), (x_right, y_top), (x_left, y_bot), (x_right, y_bot)]
    else:
        colon_gap = max(14, dw // 2)
        total_w = dw * 4 + gap * 2 + colon_gap
        start_x = cx - total_w // 2
        y0 = cy - dh // 2
        coords = [
            (start_x, y0),
            (start_x + dw + gap, y0),
            (start_x + dw * 2 + gap + colon_gap, y0),
            (start_x + dw * 3 + gap * 2 + colon_gap, y0),
        ]
        if show_colon:
            cw = max(10, min(colon_gap + 4, dw // 2 + 6))
            colon_sprite = render_styled_text_sprite(
                ":",
                cw,
                dh,
                font,
                color=clk_cfg.get("color", "#FFFFFF"),
                color2=clk_cfg.get("color2") or None,
                stroke_width=stroke_w,
                stroke_color=clk_cfg.get("stroke_color", "#000000"),
                glow_radius=glow_r,
                glow_color=clk_cfg.get("glow_color") or None,
            )
            col_x = max(0, min(W - cw, int(start_x + dw * 2 + gap + (colon_gap - cw) // 2)))
            col_y = max(0, min(H - dh, int(y0)))
            colon_info = (col_x, col_y, colon_sprite)

    clamped = [(max(0, min(W - dw, int(x))), max(0, min(H - dh, int(y)))) for x, y in coords]
    return digits, clamped, (dw, dh), colon_info


def build_seconds_assets(clk_cfg, clock_coords=None, clock_wh=(50, 70)):
    """Build independent live Seconds (01 18) digits and 2 digit coords."""
    sec_size = max(16, min(72, int(clk_cfg.get("seconds_size", max(20, int(clk_cfg.get("font_size", 60) * 0.52))))))
    sec_color = clk_cfg.get("seconds_color") or clk_cfg.get("color2") or "#FF453A"
    stroke_w = min(3, int(clk_cfg.get("stroke_width", 1)))
    stroke_col = clk_cfg.get("stroke_color", "#000000")
    glow_r = min(4, int(clk_cfg.get("glow_radius", 0)))

    digits, (sw, sh), _ = build_digit_sprites(
        font_path=clk_cfg.get("font_path"),
        font_size=sec_size,
        color=sec_color,
        stroke_width=stroke_w,
        stroke_color=stroke_col,
        glow_radius=glow_r,
        glow_color=sec_color,
        min_box=(12, 18),
        max_box=(76, 92),
        pad_extra=4,
    )
    gap = max(0, int(clk_cfg.get("seconds_spacing", 2)))
    if clk_cfg.get("seconds_x") is not None and clk_cfg.get("seconds_y") is not None:
        sx_center = int(clk_cfg["seconds_x"])
        sy_center = int(clk_cfg["seconds_y"])
    elif clock_coords:
        last_x, last_y = clock_coords[3]
        if last_x + clock_wh[0] + 10 + sw * 2 + gap <= W - 16:
            sx_center = last_x + clock_wh[0] + 10 + sw
            sy_center = last_y + clock_wh[1] - sh // 2 - 4
        else:
            sx_center = CX
            sy_center = min(H - sh // 2 - 12, last_y + clock_wh[1] + sh // 2 + 8)
    else:
        sx_center, sy_center = CX, CY + 64

    x1 = max(0, min(W - sw * 2 - gap, sx_center - (sw * 2 + gap) // 2))
    y1 = max(0, min(H - sh, sy_center - sh // 2))
    coords = [(x1, y1), (x1 + sw + gap, y1)]
    return digits, coords, (sw, sh)


def build_ampm_assets(clk_cfg, clock_coords=None, clock_wh=(50, 70)):
    """Build native AM / PM indicator (01 11, s0=AM, s1=PM)."""
    if not clk_cfg.get("show_ampm"):
        return None
    fsize = max(12, min(40, int(clk_cfg.get("ampm_size", 18))))
    col = clk_cfg.get("ampm_color") or clk_cfg.get("color", "#FFFFFF")
    sw = min(2, max(0, int(clk_cfg.get("stroke_width", 1))))
    scol = clk_cfg.get("stroke_color", "#000000")
    font = load_font(clk_cfg.get("font_path"), fsize)

    tmp = ImageDraw.Draw(Image.new("RGBA", (10, 10)))
    mw, mh = 26, 16
    for lbl in ("AM", "PM"):
        bb = tmp.textbbox((0, 0), lbl, font=font, stroke_width=sw)
        mw = max(mw, bb[2] - bb[0])
        mh = max(mh, bb[3] - bb[1])
    aw, ah = min(84, mw + sw * 2 + 8), min(52, mh + sw * 2 + 6)
    sp_am = render_styled_text_sprite("AM", aw, ah, font, color=col, stroke_width=sw, stroke_color=scol)
    sp_pm = render_styled_text_sprite("PM", aw, ah, font, color=col, stroke_width=sw, stroke_color=scol)

    if clk_cfg.get("ampm_x") is not None and clk_cfg.get("ampm_y") is not None:
        ax = int(clk_cfg["ampm_x"]) - aw // 2
        ay = int(clk_cfg["ampm_y"]) - ah // 2
    elif clock_coords:
        last_x, last_y = clock_coords[3]
        if last_x + clock_wh[0] + 6 + aw <= W - 14:
            ax = last_x + clock_wh[0] + 6
            ay = last_y + 4
        else:
            ax = max(16, clock_coords[0][0] - aw - 6)
            ay = clock_coords[0][1] + 4
    else:
        ax, ay = CX + 90, CY - 24

    ax = max(0, min(W - aw, ax))
    ay = max(0, min(H - ah, ay))
    return {"x": ax, "y": ay, "w": aw, "h": ah, "am": sp_am, "pm": sp_pm}


# --------------------------------------------------------------------------- #
# Date (01 0f Month, 01 0d Day, 01 0e Month Name, 01 10 Year YYYY)
# --------------------------------------------------------------------------- #

def build_date_assets(date_cfg):
    """
    Build live Date assets for formats:
      'MM/DD', 'DD/MM', 'MM-DD', 'DD-MM', 'DD', 'MON DD', 'DD MON', 'MON'
    Plus optional 4-digit Year (01 10).
    """
    fmt = date_cfg.get("format", "MM/DD").upper().strip()
    font_size = max(14, min(52, int(date_cfg.get("font_size", 24))))
    stroke_w = max(0, int(date_cfg.get("stroke_width", 1)))
    color = date_cfg.get("color", "#FFFFFF")
    stroke_col = date_cfg.get("stroke_color", "#000000")
    mon_upper = bool(date_cfg.get("month_uppercase", True))

    digits, (dw, dh), font = build_digit_sprites(
        font_path=date_cfg.get("font_path"),
        font_size=font_size,
        color=color,
        stroke_width=stroke_w,
        stroke_color=stroke_col,
        min_box=(10, 14),
        max_box=(64, 72),
        pad_extra=4,
    )

    cx = int(date_cfg.get("x", 233))
    cy = int(date_cfg.get("y", 132))
    gap = max(0, int(date_cfg.get("spacing", 1)))
    y0 = max(0, min(H - dh, cy - dh // 2))

    # Optional 4-digit year (01 10)
    year_info = None
    if date_cfg.get("show_year"):
        ysize = max(12, min(44, int(date_cfg.get("year_size", max(14, int(font_size * 0.85))))))
        ycol = date_cfg.get("year_color") or color
        y_digits, (ydw, ydh), _ = build_digit_sprites(
            font_path=date_cfg.get("font_path"),
            font_size=ysize,
            color=ycol,
            stroke_width=stroke_w,
            stroke_color=stroke_col,
            min_box=(9, 13),
            max_box=(54, 62),
            pad_extra=3,
        )
        ycx = int(date_cfg["year_x"]) if date_cfg.get("year_x") is not None else cx
        ycy = int(date_cfg["year_y"]) if date_cfg.get("year_y") is not None else min(H - ydh // 2 - 10, cy + dh + 6)
        ygap = max(0, gap)
        ytw = ydw * 4 + ygap * 3
        yx0 = max(0, min(W - ytw, ycx - ytw // 2))
        yy0 = max(0, min(H - ydh, ycy - ydh // 2))
        year_info = {
            "digits": y_digits,
            "wh": (ydw, ydh),
            "coords": [(yx0 + i * (ydw + ygap), yy0) for i in range(4)],
        }

    # Month Name (01 0e) modes: MON, MON DD, DD MON
    if "MON" in fmt:
        months = ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"]
        if not mon_upper:
            months = [m.capitalize() for m in months]
        tmp = ImageDraw.Draw(Image.new("RGBA", (10, 10)))
        mw, mh = 36, dh
        for m in months:
            bb = tmp.textbbox((0, 0), m, font=font, stroke_width=stroke_w)
            mw = max(mw, bb[2] - bb[0])
            mh = max(mh, bb[3] - bb[1])
        mw = min(130, mw + stroke_w * 2 + 8)
        mh = min(72, max(dh, mh + stroke_w * 2 + 6))
        m_frames = [
            render_styled_text_sprite(m, mw, mh, font, color=color, stroke_width=stroke_w, stroke_color=stroke_col)
            for m in months
        ]
        my0 = max(0, min(H - mh, cy - mh // 2))
        if fmt == "MON":
            mx0 = max(0, min(W - mw, cx - mw // 2))
            return {
                "digits": digits, "wh": (dw, dh),
                "month_coords": None, "day_coords": None, "sep": None,
                "month_name": {"x": mx0, "y": my0, "w": mw, "h": mh, "frames": m_frames},
                "year": year_info, "format": fmt,
            }
        sp_gap = max(6, gap + 5)
        day_w = dw * 2 + gap
        total_w = mw + sp_gap + day_w
        x0 = max(0, min(W - total_w, cx - total_w // 2))
        dy0 = max(0, min(H - dh, cy - dh // 2))
        if fmt.startswith("DD"):
            day_coords = [(x0, dy0), (x0 + dw + gap, dy0)]
            mx0 = x0 + day_w + sp_gap
        else:
            mx0 = x0
            dx0 = x0 + mw + sp_gap
            day_coords = [(dx0, dy0), (dx0 + dw + gap, dy0)]
        return {
            "digits": digits, "wh": (dw, dh),
            "month_coords": None, "day_coords": day_coords, "sep": None,
            "month_name": {"x": mx0, "y": my0, "w": mw, "h": mh, "frames": m_frames},
            "year": year_info, "format": fmt,
        }

    if fmt == "DD":
        total_w = dw * 2 + gap
        x0 = max(0, min(W - total_w, cx - total_w // 2))
        return {
            "digits": digits, "wh": (dw, dh),
            "month_coords": None, "day_coords": [(x0, y0), (x0 + dw + gap, y0)], "sep": None,
            "month_name": None, "year": year_info, "format": fmt,
        }

    sep_char = "-" if "-" in fmt else "/"
    sep_w = max(8, int(dw * 0.65))
    sep_sprite = render_styled_text_sprite(
        sep_char, sep_w, dh, font, color=color, stroke_width=stroke_w, stroke_color=stroke_col
    )
    total_w = dw * 4 + gap * 2 + sep_w + 2
    x0 = max(0, min(W - total_w, cx - total_w // 2))

    p1 = [(x0, y0), (x0 + dw + gap, y0)]
    sep_x = x0 + dw * 2 + gap + 1
    p2_x = sep_x + sep_w + 1
    p2 = [(p2_x, y0), (p2_x + dw + gap, y0)]

    if fmt.startswith("DD"):
        day_coords, month_coords = p1, p2
    else:
        month_coords, day_coords = p1, p2

    return {
        "digits": digits, "wh": (dw, dh),
        "month_coords": month_coords, "day_coords": day_coords,
        "sep": (sep_x, y0, sep_sprite),
        "month_name": None, "year": year_info, "format": fmt,
    }


# --------------------------------------------------------------------------- #
# Live Health Telemetry (01 06, 01 07, 01 08, 01 09, 01 15, 01 1f)
# --------------------------------------------------------------------------- #

def _draw_mini_icon(kind, size, color_rgb):
    """Draw a crisp vector mini-icon (flame, heart, steps, pin, bolt) onto a (size, size) RGBA sprite."""
    s = max(14, int(size))
    S = 2
    im = Image.new("RGBA", (s * S, s * S), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    c = (*color_rgb, 255)
    w = h = s * S

    if kind == "heart_rate":
        d.ellipse((int(w * 0.10), int(h * 0.14), int(w * 0.54), int(h * 0.58)), fill=c)
        d.ellipse((int(w * 0.46), int(h * 0.14), int(w * 0.90), int(h * 0.58)), fill=c)
        d.polygon([(int(w * 0.12), int(h * 0.40)), (int(w * 0.88), int(h * 0.40)), (w // 2, int(h * 0.90))], fill=c)
    elif kind == "calories":
        d.polygon([
            (w // 2, int(h * 0.06)), (int(w * 0.78), int(h * 0.42)), (int(w * 0.84), int(h * 0.68)),
            (int(w * 0.68), int(h * 0.92)), (int(w * 0.32), int(h * 0.92)), (int(w * 0.16), int(h * 0.68)),
            (int(w * 0.26), int(h * 0.42)),
        ], fill=c)
        inner = (min(255, color_rgb[0] + 70), min(255, color_rgb[1] + 70), min(255, color_rgb[2] + 70), 255)
        d.ellipse((int(w * 0.36), int(h * 0.56), int(w * 0.64), int(h * 0.86)), fill=inner)
    elif kind == "steps":
        d.ellipse((int(w * 0.14), int(h * 0.12), int(w * 0.44), int(h * 0.58)), fill=c)
        d.ellipse((int(w * 0.20), int(h * 0.62), int(w * 0.40), int(h * 0.82)), fill=c)
        d.ellipse((int(w * 0.56), int(h * 0.24), int(w * 0.86), int(h * 0.70)), fill=c)
        d.ellipse((int(w * 0.60), int(h * 0.74), int(w * 0.80), int(h * 0.94)), fill=c)
    elif kind == "distance":
        d.ellipse((int(w * 0.20), int(h * 0.08), int(w * 0.80), int(h * 0.66)), fill=c)
        d.polygon([(int(w * 0.24), int(h * 0.48)), (int(w * 0.76), int(h * 0.48)), (w // 2, int(h * 0.94))], fill=c)
        d.ellipse((int(w * 0.38), int(h * 0.24), int(w * 0.62), int(h * 0.48)), fill=(0, 0, 0, 220))
    else:
        d.polygon([
            (int(w * 0.58), int(h * 0.06)), (int(w * 0.20), int(h * 0.54)), (int(w * 0.48), int(h * 0.54)),
            (int(w * 0.40), int(h * 0.94)), (int(w * 0.80), int(h * 0.44)), (int(w * 0.52), int(h * 0.44)),
        ], fill=c)
    return im.resize((s, s), Image.Resampling.LANCZOS)


def build_telemetry_assets(telem_cfg):
    """Build shared digit set, HR dash glyph, Distance dot glyph, optional km/mi unit (01 1f), and active items."""
    font_size = max(14, min(44, int(telem_cfg.get("font_size", 24))))
    color = telem_cfg.get("color", "#89FC03")
    stroke_w = max(0, int(telem_cfg.get("stroke_width", 1)))
    stroke_col = telem_cfg.get("stroke_color", "#000000")

    digits, (dw, dh), font = build_digit_sprites(
        font_path=telem_cfg.get("font_path"),
        font_size=font_size,
        color=color,
        stroke_width=stroke_w,
        stroke_color=stroke_col,
        min_box=(9, 14),
        max_box=(44, 58),
        pad_extra=3,
    )

    dash_w = max(8, int(dw * 0.72))
    dash_sprite = render_styled_text_sprite(
        "-", dash_w, dh, font, color=color, stroke_width=stroke_w, stroke_color=stroke_col
    )
    dot_w = max(5, int(dw * 0.38))
    dot_sprite = Image.new("RGBA", (dot_w, dh), (0, 0, 0, 0))
    dtmp = ImageDraw.Draw(dot_sprite)
    dbb = dtmp.textbbox((0, 0), ".", font=font, stroke_width=stroke_w)
    dtw, dth = dbb[2] - dbb[0], dbb[3] - dbb[1]
    dtx = (dot_w - dtw) // 2 - dbb[0]
    dty = max(0, dh - dth - max(2, stroke_w + 1) - dbb[1])
    if stroke_w > 0:
        dtmp.text((dtx, dty), ".", font=font, fill=(*_safe_hex_rgb(stroke_col, (0, 0, 0)), 255),
                  stroke_width=stroke_w, stroke_fill=(*_safe_hex_rgb(stroke_col, (0, 0, 0)), 255))
    dtmp.text((dtx, dty), ".", font=font, fill=(*_safe_hex_rgb(color), 255))

    default_align = int(telem_cfg.get("align", 2))
    if default_align not in (0, 1, 2):
        default_align = 2

    metric_defaults = {
        "steps": (233, 336, "8420", (56, 189, 248)),
        "heart_rate": (145, 290, "72", (255, 69, 58)),
        "calories": (320, 290, "385", (255, 159, 10)),
        "distance": (233, 376, "5.42", (48, 209, 88)),
        "battery_pct": (233, 72, "85", (57, 255, 20)),
    }
    items = []
    dist_item = None
    for key, (dx, dy, sample, icon_col) in metric_defaults.items():
        sub = telem_cfg.get(key)
        if not isinstance(sub, dict) or not sub.get("enabled"):
            continue
        x = max(0, min(W - 1, int(sub.get("x", dx))))
        y = max(0, min(H - dh, int(sub.get("y", dy))))
        align = int(sub.get("align", default_align))
        if align not in (0, 1, 2):
            align = default_align
        entry = {
            "key": key,
            "x": x,
            "y": y,
            "align": align,
            "sample": sample,
            "icon_color": _safe_hex_rgb(sub.get("icon_color"), icon_col) if sub.get("icon_color") else icon_col,
        }
        items.append(entry)
        if key == "distance":
            dist_item = entry

    # Dynamic km/mi unit label (01 1f)
    dist_unit = None
    du_cfg = telem_cfg.get("distance_unit")
    du_enabled = (isinstance(du_cfg, dict) and du_cfg.get("enabled")) or bool(telem_cfg.get("show_distance_unit") or telem_cfg.get("show_dist_unit"))
    if du_enabled:
        du = du_cfg if isinstance(du_cfg, dict) else {}
        usize = max(11, min(32, int(du.get("font_size", max(12, int(font_size * 0.72))))))
        ucol = du.get("color") or color
        u_upper = bool(du.get("uppercase", False))
        ufont = load_font(telem_cfg.get("font_path"), usize)
        km_lbl, mi_lbl = ("KM", "MI") if u_upper else ("km", "mi")
        utmp = ImageDraw.Draw(Image.new("RGBA", (10, 10)))
        uw, uh = 22, 14
        for lbl in (km_lbl, mi_lbl):
            bb = utmp.textbbox((0, 0), lbl, font=ufont, stroke_width=stroke_w)
            uw = max(uw, bb[2] - bb[0])
            uh = max(uh, bb[3] - bb[1])
        uw = min(64, uw + stroke_w * 2 + 6)
        uh = min(40, uh + stroke_w * 2 + 4)
        sp_km = render_styled_text_sprite(km_lbl, uw, uh, ufont, color=ucol, stroke_width=stroke_w, stroke_color=stroke_col)
        sp_mi = render_styled_text_sprite(mi_lbl, uw, uh, ufont, color=ucol, stroke_width=stroke_w, stroke_color=stroke_col)
        if du.get("x") is not None and du.get("y") is not None:
            ux = int(du["x"]) - uw // 2
            uy = int(du["y"]) - uh // 2
        elif dist_item is not None:
            approx_w = dw * 3 + dot_w
            if dist_item["align"] == 0:
                ux = dist_item["x"] + approx_w + 4
            elif dist_item["align"] == 1:
                ux = dist_item["x"] + 4
            else:
                ux = dist_item["x"] + approx_w // 2 + 4
            uy = dist_item["y"] + max(0, dh - uh - 2)
        else:
            ux, uy = CX + 40, 380
        ux = max(0, min(W - uw, ux))
        uy = max(0, min(H - uh, uy))
        dist_unit = {"x": ux, "y": uy, "w": uw, "h": uh, "km": sp_km, "mi": sp_mi}

    return {
        "digits": digits,
        "wh": (dw, dh),
        "dash": dash_sprite,
        "dot": dot_sprite,
        "items": items,
        "dist_unit": dist_unit,
        "show_icons": bool(telem_cfg.get("show_icons", True)),
    }


def _paste_aligned_number(comp, text, digits, dot_sprite, x, y, align, dw, dh, extra_map=None):
    """Render a preview number using exact Watch 4S alignment: 0=Left, 1=Right, 2=Center."""
    extra_map = extra_map or {}
    sprites = []
    i = 0
    while i < len(text):
        matched = False
        for token, sp in extra_map.items():
            if text.startswith(token, i):
                sprites.append(sp)
                i += len(token)
                matched = True
                break
        if matched:
            continue
        ch = text[i]
        if ch == "." and dot_sprite is not None:
            sprites.append(dot_sprite)
        elif ch.isdigit():
            sprites.append(digits[int(ch)])
        i += 1
    total_w = sum(s.width for s in sprites)
    if align == 1:
        cur_x = x - total_w
    elif align == 2:
        cur_x = x - total_w // 2
    else:
        cur_x = x
    for sp in sprites:
        px = max(0, min(W - sp.width, int(cur_x)))
        py = max(0, min(H - sp.height, int(y)))
        comp.paste(sp, (px, py), sp)
        cur_x += sp.width
    return cur_x - total_w, total_w


def _composite_telemetry_icons(bg_rgba, telem_assets):
    """Render crisp mini icons beside each enabled telemetry readout."""
    if not telem_assets or not telem_assets["show_icons"] or not telem_assets["items"]:
        return bg_rgba
    out = bg_rgba.copy()
    _, dh = telem_assets["wh"]
    icon_sz = max(14, min(28, int(dh * 0.82)))
    for item in telem_assets["items"]:
        icon = _draw_mini_icon(item["key"], icon_sz, item["icon_color"])
        if item["align"] == 0:
            ix = max(6, item["x"] - icon_sz - 6)
            iy = max(6, min(H - icon_sz - 6, item["y"] + (dh - icon_sz) // 2))
        elif item["align"] == 1:
            ix = min(W - icon_sz - 6, item["x"] + 6)
            iy = max(6, min(H - icon_sz - 6, item["y"] + (dh - icon_sz) // 2))
        else:
            ix = max(6, min(W - icon_sz - 6, item["x"] - icon_sz // 2))
            iy = max(6, item["y"] - icon_sz - 4)
        out.paste(icon, (ix, iy), icon)
    return out


# --------------------------------------------------------------------------- #
# Analog Hands (01 0a): 7 Procedural Styles + Custom PNG Uploads
# --------------------------------------------------------------------------- #

def _load_custom_hand_png(path, target_len, tail_pct=14):
    """Load an uploaded transparent PNG hand (pointing up at 12 o'clock) and position pivot at (233, 233)."""
    if not path or not os.path.isfile(path):
        return None
    try:
        with Image.open(path) as im:
            raw = im.convert("RGBA")
        # Trim empty transparent margin cleanly
        bbox = raw.getbbox()
        if bbox:
            raw = raw.crop(bbox)
        target_h = max(40, min(228, int(target_len)))
        scale = target_h / max(1, raw.height)
        target_w = max(4, min(140, int(round(raw.width * scale))))
        resized = raw.resize((target_w, target_h), Image.Resampling.LANCZOS)
        tail_px = int(round(target_h * max(0.0, min(0.45, float(tail_pct) / 100.0))))
        hx = max(0, min(W - target_w, CX - target_w // 2))
        hy = max(0, min(H - target_h, CY - (target_h - tail_px)))
        return hx, hy, resized
    except Exception:
        return None


def build_analog_hands(hand_cfg):
    style = hand_cfg.get("style", "omnitrix")
    prim_hex = hand_cfg.get("color", "#39FF14")
    accent_hex = hand_cfg.get("accent_color", "#FFFFFF")
    show_sec = bool(hand_cfg.get("show_seconds", True))
    center_cap = bool(hand_cfg.get("center_cap", style != "omnitrix"))

    prim = _safe_hex_rgb(prim_hex, (57, 255, 20))
    accent = _safe_hex_rgb(accent_hex, (255, 255, 255))

    def _build_classic_set():
        out_h = []
        hw, hh = 26, 136
        hi = Image.new("RGBA", (hw, hh), (0, 0, 0, 0))
        hd = ImageDraw.Draw(hi)
        hd.polygon([(hw // 2, 4), (hw - 4, hh - 10), (hw // 2, hh), (4, hh - 10)],
                   fill=(*accent, 255), outline=(15, 18, 22, 255))
        hd.line([(hw // 2, 18), (hw // 2, hh - 18)], fill=(*prim, 255), width=4)
        out_h.append((0, CX - hw // 2, CY - hh + 12, hi))

        mw, mh = 22, 190
        mi = Image.new("RGBA", (mw, mh), (0, 0, 0, 0))
        md = ImageDraw.Draw(mi)
        md.polygon([(mw // 2, 4), (mw - 4, mh - 10), (mw // 2, mh), (4, mh - 10)],
                   fill=(*accent, 255), outline=(15, 18, 22, 255))
        md.line([(mw // 2, 18), (mw // 2, mh - 18)], fill=(*prim, 255), width=3)
        out_h.append((1, CX - mw // 2, CY - mh + 12, mi))

        sw, sh = 12, 215
        si = Image.new("RGBA", (sw, sh), (0, 0, 0, 0))
        sd = ImageDraw.Draw(si)
        sd.line([(sw // 2, 4), (sw // 2, sh)], fill=(*prim, 255), width=3)
        out_h.append((2, CX - sw // 2, CY - sh + 20, si))
        return out_h

    if style == "custom":
        fallback = {h[0]: h for h in _build_classic_set()}
        tail_pct = float(hand_cfg.get("tail_pct", hand_cfg.get("custom_tail_pct", 14)))
        hands = []
        for hid, key, def_len in ((0, "hour", 132), (1, "min", 184), (2, "sec", 208)):
            custom_len = int(hand_cfg.get(f"{key}_length", def_len))
            loaded = _load_custom_hand_png(hand_cfg.get(f"{key}_image_path"), custom_len, tail_pct)
            if loaded:
                hx, hy, himg = loaded
                hands.append((hid, hx, hy, himg))
            else:
                hands.append(fallback[hid])
    elif style == "omnitrix":
        pal = palette_from_hex(prim_hex, accent_hex)
        hands = draw_omnitrix_hands(pal)
    elif style == "omnitrix_glass":
        # Brushed silver-chrome & translucent frosted-glass Omnitrix orbital markers
        # (leaves central hologram unobstructed and stays color-neutral on green & red themes)
        hands = []
        # Hour: machined silver ring + frosted glass core at r ~ 158px
        hw, hh = 34, 178
        hi = Image.new("RGBA", (hw * 2, hh * 2), (0, 0, 0, 0))
        hd = ImageDraw.Draw(hi)
        cx2 = hw
        hd.ellipse((cx2 - 26, 10, cx2 + 26, 62), fill=(12, 16, 20, 235))
        hd.ellipse((cx2 - 22, 14, cx2 + 22, 58), fill=(214, 226, 238, 245), outline=(255, 255, 255, 255), width=2)
        hd.ellipse((cx2 - 14, 22, cx2 + 14, 50), fill=(165, 185, 205, 130), outline=(42, 52, 64, 220), width=2)
        hd.arc((cx2 - 20, 16, cx2 + 20, 56), start=200, end=330, fill=(255, 255, 255, 235), width=3)
        hands.append((0, CX - hw // 2, CY - hh, hi.resize((hw, hh), Image.Resampling.LANCZOS)))

        # Minute: sleek metallic silver capsule with frosted glass inner slit at r ~ 184px
        mw, mh = 24, 206
        mi = Image.new("RGBA", (mw * 2, mh * 2), (0, 0, 0, 0))
        md = ImageDraw.Draw(mi)
        mx2 = mw
        md.rounded_rectangle((mx2 - 15, 6, mx2 + 15, 90), radius=12, fill=(12, 16, 20, 235))
        md.rounded_rectangle((mx2 - 11, 10, mx2 + 11, 86), radius=9, fill=(224, 234, 244, 245), outline=(255, 255, 255, 255), width=2)
        md.rounded_rectangle((mx2 - 5, 18, mx2 + 5, 76), radius=4, fill=(180, 200, 220, 125), outline=(58, 70, 82, 200), width=1)
        hands.append((1, CX - mw // 2, CY - mh, mi.resize((mw, mh), Image.Resampling.LANCZOS)))

        # Second: crisp diamond chrome pip along outer bezel track at r ~ 213px
        sw, sh = 18, 222
        si = Image.new("RGBA", (sw * 2, sh * 2), (0, 0, 0, 0))
        sd = ImageDraw.Draw(si)
        sx2 = sw
        sd.polygon([(sx2, 4), (sx2 + 12, 20), (sx2, 36), (sx2 - 12, 20)], fill=(12, 16, 20, 235))
        sd.polygon([(sx2, 8), (sx2 + 8, 20), (sx2, 32), (sx2 - 8, 20)], fill=(242, 248, 255, 250))
        sd.polygon([(sx2, 13), (sx2 + 4, 20), (sx2, 27), (sx2 - 4, 20)], fill=(190, 215, 235, 150))
        hands.append((2, CX - sw // 2, CY - sh, si.resize((sw, sh), Image.Resampling.LANCZOS)))
    elif style == "stark_hud":
        hands = []
        # Glowing cyan/accent HUD laser reticle pointers
        for hid, sw, sh, lw, col in ((0, 30, 134, 4, prim), (1, 26, 186, 3, accent), (2, 18, 212, 2, prim)):
            img = Image.new("RGBA", (sw, sh), (0, 0, 0, 0))
            d = ImageDraw.Draw(img)
            d.polygon([(sw // 2, 4), (sw // 2 + 7, 22), (sw // 2, 16), (sw // 2 - 7, 22)], fill=(*col, 255))
            d.line([(sw // 2, 16), (sw // 2, sh - 6)], fill=(*col, 240), width=lw)
            if hid != 2:
                d.ellipse((sw // 2 - 5, sh // 2 - 5, sw // 2 + 5, sh // 2 + 5), outline=(*accent, 255), width=2)
            glow = img.filter(ImageFilter.GaussianBlur(radius=3))
            img = Image.alpha_composite(glow, img)
            hands.append((hid, CX - sw // 2, CY - sh + 10, img))
    elif style == "dauphine":
        hands = []
        # Faceted luxury skeleton dauphine hands (two-tone bevel)
        dark_side = tuple(max(12, int(c * 0.55)) for c in accent)
        for hid, sw, sh, tail in ((0, 28, 140, 18), (1, 22, 194, 22)):
            img = Image.new("RGBA", (sw, sh), (0, 0, 0, 0))
            d = ImageDraw.Draw(img)
            mid = sw // 2
            d.polygon([(mid, 2), (sw - 3, sh - tail), (mid, sh)], fill=(*accent, 255))
            d.polygon([(mid, 2), (3, sh - tail), (mid, sh)], fill=(*dark_side, 255))
            d.polygon([(mid, 24), (mid + 4, sh - tail - 8), (mid, sh - tail - 2), (mid - 4, sh - tail - 8)], fill=(0, 0, 0, 0))
            d.line([(mid, 22), (mid, sh - tail - 10)], fill=(*prim, 255), width=2)
            hands.append((hid, CX - mid, CY - sh + tail, img))
        si = Image.new("RGBA", (14, 220), (0, 0, 0, 0))
        sd = ImageDraw.Draw(si)
        sd.line([(7, 4), (7, 214)], fill=(*prim, 255), width=2)
        sd.ellipse((3, 196, 11, 204), fill=(*prim, 255))
        hands.append((2, CX - 7, CY - 190, si))
    elif style == "pixel":
        hands = []
        for hid, sw, sh, blk, col in ((0, 20, 128, 6, prim), (1, 16, 180, 4, accent), (2, 10, 206, 2, prim)):
            img = Image.new("RGBA", (sw, sh), (0, 0, 0, 0))
            d = ImageDraw.Draw(img)
            mid = sw // 2
            d.rectangle((mid - blk, 8, mid + blk, sh - 2), fill=(*col, 255), outline=(12, 14, 18, 255))
            d.rectangle((mid - blk // 2, 2, mid + blk // 2, 10), fill=(*accent, 255))
            hands.append((hid, CX - mid, CY - sh + 8, img))
    elif style == "neon":
        hands = []
        for hid, sw, sh, lw, col in ((0, 26, 130, 6, prim), (1, 22, 182, 4, accent), (2, 18, 206, 2, prim)):
            img = Image.new("RGBA", (sw, sh), (0, 0, 0, 0))
            d = ImageDraw.Draw(img)
            d.line([(sw // 2, 10), (sw // 2, sh - 4)], fill=(*col, 255), width=lw)
            glow = img.filter(ImageFilter.GaussianBlur(radius=4))
            img = Image.alpha_composite(glow, img)
            hands.append((hid, CX - sw // 2, CY - sh, img))
    elif style == "minimal":
        hands = []
        for hid, sw, sh, r, col in ((0, 18, 128, 5, accent), (1, 14, 180, 4, accent), (2, 10, 206, 2, prim)):
            img = Image.new("RGBA", (sw, sh), (0, 0, 0, 0))
            d = ImageDraw.Draw(img)
            d.rounded_rectangle((sw // 2 - r, 4, sw // 2 + r, sh - 2), radius=r, fill=(*col, 255))
            hands.append((hid, CX - sw // 2, CY - sh, img))
    else:
        hands = _build_classic_set()

    if not show_sec:
        hands = [h for h in hands if h[0] != 2]

    cap_img = None
    if style == "custom" and hand_cfg.get("cap_image_path") and os.path.isfile(hand_cfg["cap_image_path"]):
        try:
            with Image.open(hand_cfg["cap_image_path"]) as cim:
                cap_img = _prepare_circular_pil(cim.convert("RGBA"), max(16, min(64, int(hand_cfg.get("cap_size", 28)))), circular=False)
        except Exception:
            cap_img = None
    elif center_cap:
        cap_size = 24
        cap_img = Image.new("RGBA", (cap_size, cap_size), (0, 0, 0, 0))
        cd = ImageDraw.Draw(cap_img)
        cd.ellipse((1, 1, cap_size - 2, cap_size - 2), fill=(25, 30, 36, 255), outline=(*accent, 255), width=2)
        cd.ellipse((7, 7, cap_size - 8, cap_size - 8), fill=(*prim, 255))

    return hands, cap_img


# --------------------------------------------------------------------------- #
# Multiple Progress Gauges (01 12) + Native Dynamic Battery Bar (01 05)
# --------------------------------------------------------------------------- #

def normalize_gauges(config):
    """Return list of gauge configs, transparently migrating legacy single config['battery']."""
    if isinstance(config.get("gauges"), list):
        return [g for g in config["gauges"] if isinstance(g, dict)]
    b = config.get("battery")
    if isinstance(b, dict) and b.get("enabled"):
        g = dict(b)
        g.setdefault("id", "g1")
        g.setdefault("kind", "native_battery_bar" if g.get("style") == "native_bar" else "progress")
        return [g]
    return []


def build_native_battery_bar(g_cfg):
    """
    Build native Watch 4S dynamic battery bar (opcode `01 05`).
    Matches official LS26_id_123: battery frame sprite with solid filled interior + (padX, padY, fillW, fillH, 3).
    """
    bw = max(36, min(140, int(g_cfg.get("width", 56))))
    bh = max(16, min(52, int(g_cfg.get("height", 26))))
    col = _safe_hex_rgb(g_cfg.get("color", "#39FF14"))
    border = _safe_hex_rgb(g_cfg.get("border_color", "#E2E8F0"))

    nub_w = max(4, bw // 12)
    body_w = bw - nub_w
    pad_x = 4
    pad_y = 4
    fill_w = max(8, body_w - pad_x * 2)
    fill_h = max(6, bh - pad_y * 2)

    img = Image.new("RGBA", (bw, bh), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((0, 0, body_w - 1, bh - 1), radius=4, fill=(14, 18, 24, 210), outline=(*border, 245), width=2)
    d.rounded_rectangle((body_w, bh // 4, bw - 1, bh - bh // 4 - 1), radius=2, fill=(*border, 245))
    d.rectangle((pad_x, pad_y, pad_x + fill_w - 1, pad_y + fill_h - 1), fill=(*col, 255))

    bx = max(0, min(W - bw, int(g_cfg.get("x", 233)) - bw // 2))
    by = max(0, min(H - bh, int(g_cfg.get("y", 405)) - bh // 2))
    return {
        "x": bx, "y": by, "w": bw, "h": bh, "sprite": img,
        "pad_x": pad_x, "pad_y": pad_y, "fill_w": fill_w, "fill_h": fill_h, "style_byte": 3,
    }


def build_battery_widget(batt_cfg):
    """Build 11-frame progress gauge (0%, 10%, ..., 100%) for Battery, Steps, Calories, Distance, or Active."""
    style = batt_cfg.get("style", "ring")
    col_rgb = _safe_hex_rgb(batt_cfg.get("color", "#39FF14"))
    thickness = max(3, min(16, int(batt_cfg.get("thickness", 6))))
    metric = batt_cfg.get("metric", "battery")
    low_red = (metric == "battery")
    inset = max(4, min(120, int(batt_cfg.get("radius_inset", batt_cfg.get("inset", 4 if style == "ring" else 14)))))
    if style == "inner_ring":
        inset = max(16, int(batt_cfg.get("radius_inset", batt_cfg.get("inset", 20))))
    frames = []

    if style == "omnitrix_low_red":
        # Auto-shift full faceplate to Red Timeout Omnitrix when battery < threshold_pct (default 50%).
        # Frames < threshold share one Red Omnitrix RLE blob; frames >= threshold share one transparent blob.
        threshold_pct = max(10, min(90, int(batt_cfg.get("threshold_pct", 50))))
        omni_style = batt_cfg.get("omni_style", "alien_force")
        if omni_style not in ("alien_force", "os", "omniverse", "5yl"):
            omni_style = "alien_force"
        glow = float(batt_cfg.get("omni_glow", 1.0))
        ticks = bool(batt_cfg.get("omni_ticks", True))
        brightness = float(batt_cfg.get("brightness", 90))
        red_hex = batt_cfg.get("color", "#ff1818")
        red_img = draw_omnitrix_bg(style=omni_style, palette=palette_from_hex(red_hex), show_ticks=ticks, glow_strength=glow)
        red_img = apply_amoled_dimmer(red_img, brightness, 0)
        blank = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        for step in range(11):
            frames.append(red_img if (step * 10 < threshold_pct) else blank)
        return 0, 0, frames

    if style in ("ring", "inner_ring"):
        bbox = (inset, inset, W - 1 - inset, H - 1 - inset)
        for step in range(11):
            img = Image.new("RGBA", (W, H), (0, 0, 0, 0))
            d = ImageDraw.Draw(img)
            d.arc(bbox, start=-90, end=270, fill=(28, 34, 38, 170), width=thickness)
            if step > 0:
                sweep = int(360 * step / 10)
                c = (255, 45, 45, 255) if (low_red and step <= 2) else (*col_rgb, 255)
                d.arc(bbox, start=-90, end=-90 + sweep, fill=c, width=thickness)
            frames.append(img)
        return 0, 0, frames

    arc_specs = {
        "arc":       (35, 145, True),    # Bottom 110 deg
        "top_arc":   (-145, -35, False), # Top 110 deg
        "left_arc":  (130, 230, False),  # Left 100 deg
        "right_arc": (-50, 50, False),   # Right 100 deg
    }
    if style in arc_specs:
        a_start, a_end, reverse = arc_specs[style]
        span = a_end - a_start
        bbox = (inset, inset, W - 1 - inset, H - 1 - inset)
        for step in range(11):
            img = Image.new("RGBA", (W, H), (0, 0, 0, 0))
            d = ImageDraw.Draw(img)
            d.arc(bbox, start=a_start, end=a_end, fill=(35, 42, 50, 190), width=thickness + 2)
            if step > 0:
                sweep = int(span * step / 10)
                c = (255, 45, 45, 255) if (low_red and step <= 2) else (*col_rgb, 255)
                if reverse:
                    d.arc(bbox, start=a_end - sweep, end=a_end, fill=c, width=thickness + 2)
                else:
                    d.arc(bbox, start=a_start, end=a_start + sweep, fill=c, width=thickness + 2)
            frames.append(img)
        return 0, 0, frames

    if style == "bar":
        bw = max(60, min(260, int(batt_cfg.get("width", 120))))
        bh = max(12, thickness + 8)
        bx = max(0, min(W - bw, int(batt_cfg.get("x", 233)) - bw // 2))
        by = max(0, min(H - bh, int(batt_cfg.get("y", 405)) - bh // 2))
        for step in range(11):
            img = Image.new("RGBA", (bw, bh), (0, 0, 0, 0))
            d = ImageDraw.Draw(img)
            d.rounded_rectangle(
                (0, 0, bw - 1, bh - 1), radius=bh // 2,
                fill=(20, 25, 32, 210), outline=(90, 105, 120, 220), width=2,
            )
            if step > 0:
                fw = max(6, int((bw - 6) * step / 10))
                c = (255, 45, 45, 255) if (low_red and step <= 2) else (*col_rgb, 255)
                d.rounded_rectangle((3, 3, 3 + fw, bh - 4), radius=(bh - 6) // 2, fill=c)
            frames.append(img)
        return bx, by, frames

    bw, bh = 62, 28
    bx = max(0, min(W - bw, int(batt_cfg.get("x", 233)) - bw // 2))
    by = max(0, min(H - bh, int(batt_cfg.get("y", 405)) - bh // 2))
    for step in range(11):
        img = Image.new("RGBA", (bw, bh), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        d.rounded_rectangle((1, 2, bw - 8, bh - 3), radius=6, fill=(15, 20, 25, 210), outline=(220, 230, 240, 235), width=2)
        d.rounded_rectangle((bw - 6, 8, bw - 2, bh - 9), radius=2, fill=(220, 230, 240, 235))
        if step > 0:
            fw = max(4, int((bw - 15) * step / 10))
            c = (255, 45, 45, 255) if (low_red and step <= 2) else (*col_rgb, 255)
            d.rounded_rectangle((5, 6, 5 + fw, bh - 7), radius=3, fill=c)
        frames.append(img)
    return bx, by, frames


# --------------------------------------------------------------------------- #
# Weekday (01 04), Custom PNG Overlays (01 00), Custom Text Labels (01 00)
# --------------------------------------------------------------------------- #

def build_weekday_widget(wk_cfg):
    """Build 7-frame weekday widget (SUN..SAT). Returns (x, y, frames)."""
    font_size = max(16, min(48, int(wk_cfg.get("font_size", 24))))
    font = load_font(wk_cfg.get("font_path"), font_size)
    upper = bool(wk_cfg.get("uppercase", True))
    labels = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"] if upper else ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
    stroke_w = int(wk_cfg.get("stroke_width", 1))

    tmp = ImageDraw.Draw(Image.new("RGBA", (10, 10)))
    max_w, max_h = 50, 24
    for lbl in labels:
        bb = tmp.textbbox((0, 0), lbl, font=font, stroke_width=stroke_w)
        max_w = max(max_w, bb[2] - bb[0])
        max_h = max(max_h, bb[3] - bb[1])
    ww = min(140, max_w + stroke_w * 2 + 12)
    wh = min(70, max_h + stroke_w * 2 + 10)

    frames = [
        render_styled_text_sprite(
            lbl, ww, wh, font,
            color=wk_cfg.get("color", "#FFFFFF"),
            stroke_width=stroke_w,
            stroke_color=wk_cfg.get("stroke_color", "#000000"),
        )
        for lbl in labels
    ]
    wx = max(0, min(W - ww, int(wk_cfg.get("x", 233)) - ww // 2))
    wy = max(0, min(H - wh, int(wk_cfg.get("y", 95)) - wh // 2))
    return wx, wy, frames


def build_overlay_sprite(ov_cfg):
    """Load and transform a custom PNG sticker/frame/HUD overlay for opcode `01 00`."""
    if not ov_cfg or not ov_cfg.get("enabled", True):
        return None
    p = ov_cfg.get("image_path")
    if not p or not os.path.isfile(p):
        return None
    try:
        with Image.open(p) as im:
            raw = im.convert("RGBA")
        target_w = max(20, min(W, int(ov_cfg.get("size", ov_cfg.get("width", 140)))))
        if ov_cfg.get("keep_aspect", True):
            scale = target_w / max(1, max(raw.width, raw.height))
            rw = max(8, min(W, int(round(raw.width * scale))))
            rh = max(8, min(H, int(round(raw.height * scale))))
        else:
            rw = max(8, min(W, int(ov_cfg.get("width", target_w))))
            rh = max(8, min(H, int(ov_cfg.get("height", target_w))))
        img = raw.resize((rw, rh), Image.Resampling.LANCZOS)
        rot = float(ov_cfg.get("rotation", 0))
        if abs(rot) > 0.5:
            img = img.rotate(-rot, resample=Image.Resampling.BICUBIC, expand=True)
            if img.width > W or img.height > H:
                img.thumbnail((W, H), Image.Resampling.LANCZOS)
        img = _apply_opacity(img, ov_cfg.get("opacity", 100))
        ox = max(0, min(W - img.width, int(ov_cfg.get("x", CX)) - img.width // 2))
        oy = max(0, min(H - img.height, int(ov_cfg.get("y", CY)) - img.height // 2))
        return {"x": ox, "y": oy, "w": img.width, "h": img.height, "sprite": img}
    except Exception:
        return None


def build_text_label_sprite(lbl_cfg):
    """Render a custom static text label / badge for opcode `01 00`."""
    if not lbl_cfg or not lbl_cfg.get("enabled", True):
        return None
    text = str(lbl_cfg.get("text", "")).strip()[:40]
    if not text:
        return None
    if lbl_cfg.get("uppercase"):
        text = text.upper()
    fsize = max(12, min(64, int(lbl_cfg.get("font_size", 22))))
    sw = max(0, min(6, int(lbl_cfg.get("stroke_width", 1))))
    glow = max(0, min(10, int(lbl_cfg.get("glow_radius", 0))))
    font = load_font(lbl_cfg.get("font_path"), fsize)
    tmp = ImageDraw.Draw(Image.new("RGBA", (10, 10)))
    bb = tmp.textbbox((0, 0), text, font=font, stroke_width=sw)
    pad = sw * 2 + glow * 2 + 8
    tw = min(W - 8, max(20, int(bb[2] - bb[0] + pad)))
    th = min(H - 8, max(18, int(bb[3] - bb[1] + pad)))
    sp = render_styled_text_sprite(
        text, tw, th, font,
        color=lbl_cfg.get("color", "#FFFFFF"),
        color2=lbl_cfg.get("color2") or None,
        stroke_width=sw,
        stroke_color=lbl_cfg.get("stroke_color", "#000000"),
        glow_radius=glow,
        glow_color=lbl_cfg.get("glow_color") or lbl_cfg.get("color", "#FFFFFF"),
    )
    sp = _apply_opacity(sp, lbl_cfg.get("opacity", 100))
    lx = max(0, min(W - tw, int(lbl_cfg.get("x", CX)) - tw // 2))
    ly = max(0, min(H - th, int(lbl_cfg.get("y", 160)) - th // 2))
    return {"x": lx, "y": ly, "w": tw, "h": th, "sprite": sp}


# --------------------------------------------------------------------------- #
# Layer Z-Order & Multi-Zone Animated Sprites Normalization
# --------------------------------------------------------------------------- #

def normalize_anim_sprites(config):
    """Return list of enabled animated sprite configs (supports both anim_sprites[] and legacy bg animated_gif)."""
    out = []
    bg = config.get("background", {})
    if bg.get("mode") == "animated_gif" and bg.get("image_path") and os.path.isfile(bg["image_path"]):
        out.append({
            "id": "bg_anim",
            "is_bg_anim": True,
            "enabled": True,
            "image_path": bg["image_path"],
            "frames": bg.get("anim_frames", 8),
            "fps": bg.get("anim_fps", 4),
            "size": bg.get("anim_size", W),
            "x": bg.get("anim_x", CX),
            "y": bg.get("anim_y", CY),
            "circular": bg.get("anim_circular", True),
            "brightness": bg.get("brightness", 100),
            "vignette": bg.get("vignette", 0),
        })
    for idx, sp in enumerate(config.get("anim_sprites") or []):
        if not isinstance(sp, dict) or not sp.get("enabled", True):
            continue
        if sp.get("image_path") and os.path.isfile(sp["image_path"]):
            item = dict(sp)
            item.setdefault("id", f"anim_{idx + 1}")
            item["is_bg_anim"] = False
            out.append(item)
    return out[:3]


def resolve_layer_order(config):
    """
    Build the exact back-to-front layer order list (supports both group keys and individual
    item keys like 'anim:a1', 'overlay:o1', 'text:t1', 'gauge:g1').
    """
    aliases = {"digital_clock": "clock", "analog_hands": "hands", "battery": "gauges"}
    raw = config.get("layer_order")
    order = []
    if isinstance(raw, list) and raw:
        for x in raw:
            tok = aliases.get(str(x), str(x))
            if tok not in order:
                order.append(tok)
    else:
        order = list(DEFAULT_LAYER_ORDER)
    # Guarantee background is first if not explicitly repositioned, and append any missing default groups
    for key in DEFAULT_LAYER_ORDER:
        if key not in order:
            if key == "background":
                order.insert(0, key)
            else:
                order.append(key)
    return order


# --------------------------------------------------------------------------- #
# Unified Preview Renderer (Static + Animated GIF, Respecting Z-Order!)
# --------------------------------------------------------------------------- #

def _render_scene(config, anim_frame_idx=0, sec_val=35, blink_on=True, prebuilt_anims=None):
    """Render a 466x466 RGBA preview frame respecting config['layer_order'] back-to-front."""
    comp = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    bg_cfg = config.get("background", {})

    # Pre-build dynamic groups so individual Z-order entries can reference them
    gauges = {g.get("id", f"g{i+1}"): g for i, g in enumerate(normalize_gauges(config)) if g.get("enabled", True)}
    overlays = {o.get("id", f"ov{i+1}"): o for i, o in enumerate(config.get("overlays") or []) if isinstance(o, dict) and o.get("enabled", True)}
    texts = {t.get("id", f"txt{i+1}"): t for i, t in enumerate(config.get("text_labels") or []) if isinstance(t, dict) and t.get("enabled", True)}
    anims = prebuilt_anims if prebuilt_anims is not None else {}
    if prebuilt_anims is None:
        for sp in normalize_anim_sprites(config):
            frs, rect, _, _ = extract_animated_frames(sp, override_count=2)
            if frs:
                anims[sp["id"]] = (frs, rect)

    emitted_gauges, emitted_overlays, emitted_texts, emitted_anims = set(), set(), set(), set()

    def draw_gauge(g):
        if g.get("kind") == "native_battery_bar" or g.get("style") == "native_bar":
            nb = build_native_battery_bar(g)
            sp = nb["sprite"].copy()
            # Preview 80% fill by clearing rightmost 20% of inner fill box
            d = ImageDraw.Draw(sp)
            cut_x = nb["pad_x"] + int(nb["fill_w"] * 0.80)
            d.rectangle((cut_x, nb["pad_y"], nb["pad_x"] + nb["fill_w"] - 1, nb["pad_y"] + nb["fill_h"] - 1), fill=(14, 18, 24, 210))
            comp.paste(sp, (nb["x"], nb["y"]), sp)
        else:
            bx, by, bframes = build_battery_widget(g)
            preview_idx = 2 if (g.get("style") == "omnitrix_low_red" and g.get("preview_low")) else 8
            comp.paste(bframes[preview_idx], (bx, by), bframes[preview_idx])

    def draw_overlay(o):
        ov = build_overlay_sprite(o)
        if ov:
            comp.paste(ov["sprite"], (ov["x"], ov["y"]), ov["sprite"])

    def draw_text(t):
        lb = build_text_label_sprite(t)
        if lb:
            comp.paste(lb["sprite"], (lb["x"], lb["y"]), lb["sprite"])

    def draw_anim(aid):
        if aid not in anims:
            return
        frs, (ax, ay, _, _) = anims[aid]
        fr = frs[anim_frame_idx % len(frs)]
        comp.paste(fr, (ax, ay), fr)

    for token in resolve_layer_order(config):
        if token == "background":
            bg_img = _build_solid_gradient_bg(bg_cfg) if bg_cfg.get("mode") == "animated_gif" else build_background(bg_cfg)
            comp.paste(bg_img, (0, 0), bg_img)
            if "bg_anim" in anims and "anim:bg_anim" not in resolve_layer_order(config):
                draw_anim("bg_anim")
                emitted_anims.add("bg_anim")

        elif token == "tap_switch":
            ts_cfg = config.get("tap_switch", {})
            tx, ty, ts_frames = build_tap_switch_assets(ts_cfg)
            if ts_frames:
                pidx = int(ts_cfg.get("preview_index", 0)) % len(ts_frames)
                comp.paste(ts_frames[pidx], (tx, ty), ts_frames[pidx])

        elif token == "bezel":
            bz = build_bezel_layer(config.get("bezel", {}))
            if bz is not None:
                comp = Image.alpha_composite(comp, bz)

        elif token == "anim_sprites":
            for aid in list(anims.keys()):
                if aid not in emitted_anims:
                    draw_anim(aid)
                    emitted_anims.add(aid)
        elif token.startswith("anim:"):
            aid = token.split(":", 1)[1]
            if aid in anims and aid not in emitted_anims:
                draw_anim(aid)
                emitted_anims.add(aid)

        elif token == "gauges":
            for gid, g in gauges.items():
                if gid not in emitted_gauges:
                    draw_gauge(g)
                    emitted_gauges.add(gid)
        elif token.startswith("gauge:"):
            gid = token.split(":", 1)[1]
            if gid in gauges and gid not in emitted_gauges:
                draw_gauge(gauges[gid])
                emitted_gauges.add(gid)

        elif token == "overlays":
            for oid, o in overlays.items():
                if oid not in emitted_overlays:
                    draw_overlay(o)
                    emitted_overlays.add(oid)
        elif token.startswith("overlay:"):
            oid = token.split(":", 1)[1]
            if oid in overlays and oid not in emitted_overlays:
                draw_overlay(overlays[oid])
                emitted_overlays.add(oid)

        elif token == "text_labels":
            for tid, t in texts.items():
                if tid not in emitted_texts:
                    draw_text(t)
                    emitted_texts.add(tid)
        elif token.startswith("text:"):
            tid = token.split(":", 1)[1]
            if tid in texts and tid not in emitted_texts:
                draw_text(texts[tid])
                emitted_texts.add(tid)

        elif token == "weather":
            wa = build_weather_assets(config.get("weather", {}))
            if wa:
                if wa["icon"]:
                    ic = wa["icon"]
                    fr = ic["frames"][ic["preview_state"]]
                    comp.paste(fr, (ic["x"], ic["y"]), fr)
                if wa["temp"]:
                    tp = wa["temp"]
                    unit_sp = tp["degf"] if tp["unit_preview"] == "F" else tp["degc"]
                    sample = "72U" if tp["unit_preview"] == "F" else "24U"
                    _paste_aligned_number(
                        comp, sample, tp["digits"], None, tp["x"], tp["y"], tp["align"],
                        tp["wh"][0], tp["wh"][1], extra_map={"-": tp["minus"], "U": unit_sp},
                    )

        elif token == "bluetooth":
            bt = build_bluetooth_assets(config.get("bluetooth", {}))
            if bt:
                sp = bt["connected"] if bt["preview_connected"] else bt["disconnected"]
                comp.paste(sp, (bt["x"], bt["y"]), sp)

        elif token == "weekday":
            wk_cfg = config.get("weekday", {})
            if wk_cfg.get("enabled"):
                wx, wy, wframes = build_weekday_widget(wk_cfg)
                comp.paste(wframes[4], (wx, wy), wframes[4])  # THU

        elif token == "date":
            date_cfg = config.get("date", {})
            if date_cfg.get("enabled"):
                da = build_date_assets(date_cfg)
                if da["month_name"]:
                    mn = da["month_name"]
                    comp.paste(mn["frames"][10], (mn["x"], mn["y"]), mn["frames"][10])  # NOV
                if da["month_coords"]:
                    for dv, (dx, dy) in zip([1, 1], da["month_coords"]):
                        comp.paste(da["digits"][dv], (dx, dy), da["digits"][dv])
                if da["sep"]:
                    sx, sy, ssp = da["sep"]
                    comp.paste(ssp, (sx, sy), ssp)
                if da["day_coords"]:
                    for dv, (dx, dy) in zip([2, 6], da["day_coords"]):
                        comp.paste(da["digits"][dv], (dx, dy), da["digits"][dv])
                if da["year"]:
                    yr = da["year"]
                    for dv, (dx, dy) in zip([2, 0, 2, 6], yr["coords"]):
                        comp.paste(yr["digits"][dv], (dx, dy), yr["digits"][dv])

        elif token == "clock":
            clk_cfg = config.get("digital_clock", {})
            if clk_cfg.get("enabled"):
                digits, coords, cwh, colon_info = build_digital_clock_assets(clk_cfg)
                for dval, (dx, dy) in zip([1, 0, 1, 0], coords):
                    comp.paste(digits[dval], (dx, dy), digits[dval])
                if colon_info and blink_on:
                    col_x, col_y, col_sp = colon_info
                    comp.paste(col_sp, (col_x, col_y), col_sp)
                if clk_cfg.get("show_seconds"):
                    s_digits, s_coords, _ = build_seconds_assets(clk_cfg, coords, cwh)
                    for dval, (dx, dy) in zip([sec_val // 10, sec_val % 10], s_coords):
                        comp.paste(s_digits[dval], (dx, dy), s_digits[dval])
                ampm = build_ampm_assets(clk_cfg, coords, cwh)
                if ampm:
                    comp.paste(ampm["am"], (ampm["x"], ampm["y"]), ampm["am"])

        elif token == "telemetry":
            telem_cfg = config.get("telemetry", {})
            if telem_cfg.get("enabled"):
                ta = build_telemetry_assets(telem_cfg)
                if ta["items"]:
                    comp = _composite_telemetry_icons(comp, ta)
                    dw, dh = ta["wh"]
                    for item in ta["items"]:
                        _paste_aligned_number(comp, item["sample"], ta["digits"], ta["dot"], item["x"], item["y"], item["align"], dw, dh)
                if ta["dist_unit"]:
                    du = ta["dist_unit"]
                    comp.paste(du["km"], (du["x"], du["y"]), du["km"])

        elif token == "hands":
            hand_cfg = config.get("analog_hands", {})
            if hand_cfg.get("enabled"):
                hands, cap_img = build_analog_hands(hand_cfg)
                angles = {0: -305, 1: -60, 2: -210}
                for hid, hx, hy, himg in hands:
                    full = Image.new("RGBA", (W, H), (0, 0, 0, 0))
                    full.paste(himg, (hx, hy))
                    rot = full.rotate(angles[hid], resample=Image.Resampling.BICUBIC, center=(CX, CY))
                    comp = Image.alpha_composite(comp, rot)
                if cap_img is not None:
                    comp.paste(cap_img, (CX - cap_img.width // 2, CY - cap_img.height // 2), cap_img)

    # Circular AMOLED mask final clip
    mask = Image.new("L", (W, H), 0)
    ImageDraw.Draw(mask).ellipse((0, 0, W - 1, H - 1), fill=255)
    final = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    final.paste(comp, (0, 0), mask)
    return final


def render_config_preview(config):
    """Render an exact 466x466 RGBA static preview of any multi-layer watchface config."""
    return _render_scene(config)


def render_config_animated_preview(config):
    """
    If config uses any multi-frame animated GIF/WebP sprite (`01 2e`), return
    (list_of_466x466_RGBA_frames, duration_ms). Otherwise return (None, 0).
    """
    anim_specs = normalize_anim_sprites(config)
    if not anim_specs:
        return None, 0
    prebuilt = {}
    max_n = 0
    best_ms = 250
    for sp in anim_specs:
        frs, rect, _, dur_ms = extract_animated_frames(sp)
        if len(frs) >= 2:
            prebuilt[sp["id"]] = (frs, rect)
            if len(frs) > max_n:
                max_n = len(frs)
                best_ms = dur_ms
    if max_n < 2:
        return None, 0
    out_frames = [
        _render_scene(config, anim_frame_idx=i, sec_val=(35 + i) % 60, blink_on=(i % 2 == 0), prebuilt_anims=prebuilt)
        for i in range(max_n)
    ]
    return out_frames, best_ms


# --------------------------------------------------------------------------- #
# Watch 4S Binary Packer (`_pack_watchface_binary` + `compile_config_to_bin`)
# --------------------------------------------------------------------------- #

def _pack_watchface_binary(*, has_anim_header, digit_tables, layout_items, prev_blob):
    """Assemble a complete Watch 4S `.bin` byte buffer from pre-encoded RLE blobs."""
    has_tables = has_anim_header or len(digit_tables) > 0

    dt_off = 0x0010 if has_tables else 0x0000
    table_len = 0
    if has_anim_header:
        table_len += len(ANIM_RESOURCE_PREFIX)  # 8 bytes: 00 02 00 00 00 02 01 00
    table_len += len(digit_tables) * 83
    if has_tables:
        table_len += 2
    layout_off = (0x0010 + table_len) if has_tables else 0x0010

    # Compute exact layout stream length
    layout_size = 0
    for item in layout_items:
        kind = item["kind"]
        if kind == "static":
            layout_size += 14
        elif kind == "anim":
            layout_size += 15 + len(item["blobs"]) * 4
        elif kind == "clock":
            layout_size += 34
        elif kind == "two_digit":
            layout_size += 12
        elif kind == "weekday":
            layout_size += 7 + len(item["blobs"]) * 8
        elif kind == "native_battery_bar":
            layout_size += 19
        elif kind == "progress":
            layout_size += 8 + len(item["blobs"]) * 8
        elif kind == "dash_glyph":
            layout_size += 10
        elif kind in ("heart_rate", "steps"):
            layout_size += 26
        elif kind == "calories":
            layout_size += 17
        elif kind == "distance":
            layout_size += 42
        elif kind == "battery_pct":
            layout_size += 8
        elif kind == "hand":
            layout_size += 19
        elif kind == "month_name":
            layout_size += 198
        elif kind == "year":
            layout_size += 23
        elif kind == "ampm":
            layout_size += 27
        elif kind == "bluetooth":
            layout_size += 23
        elif kind == "tap_switch":
            layout_size += 8 + len(item["blobs"]) * 8
        elif kind == "weather_icon":
            layout_size += 7 + len(item["blobs"]) * 8
        elif kind == "temperature":
            layout_size += 32
        elif kind == "dist_unit":
            layout_size += 22
    layout_size += 2

    header_total = layout_off + layout_size
    img_start = (header_total + 3) & ~3
    if not has_anim_header and len(digit_tables) == 1 and len(layout_items) == 2 and layout_items[1]["kind"] == "clock":
        img_start = max(0x98, img_start)

    out = bytearray(img_start)
    blob_cache = {}

    def append_blob(blob):
        cached = blob_cache.get(blob)
        if cached is not None:
            return cached
        off = len(out)
        out.extend(blob)
        pad4_ff(out)
        blob_cache[blob] = off
        return off

    item_offs = []
    for item in layout_items:
        kind = item["kind"]
        if kind in ("static", "dash_glyph", "hand", "native_battery_bar"):
            item_offs.append(append_blob(item["blob"]))
        elif kind in ("anim", "weekday", "progress", "month_name", "tap_switch", "weather_icon"):
            item_offs.append([append_blob(b) for b in item["blobs"]])
        elif kind == "clock":
            col_blob = item.get("colon_blob")
            item_offs.append(append_blob(col_blob) if col_blob is not None else 0)
        elif kind == "distance":
            item_offs.append(append_blob(item["dot_blob"]))
        elif kind in ("ampm", "bluetooth", "dist_unit"):
            item_offs.append([append_blob(item["blob0"]), append_blob(item["blob1"])])
        elif kind == "temperature":
            item_offs.append([append_blob(item["minus_blob"]), append_blob(item["degc_blob"]), append_blob(item["degf_blob"])])
        else:
            item_offs.append(None)

    dt_offs = [[append_blob(blob) for blob, _, _ in tbl] for tbl in digit_tables]
    prev_off = append_blob(prev_blob)

    if has_tables:
        tp = 0x10
        if has_anim_header:
            out[tp : tp + 8] = ANIM_RESOURCE_PREFIX
            tp += 8
        for tid, (tbl, offs) in enumerate(zip(digit_tables, dt_offs)):
            out[tp : tp + 3] = bytes([0x01, 0x01, tid])
            tp += 3
            for i in range(10):
                _, dw, dh = tbl[i]
                struct.pack_into("<IHH", out, tp + i * 8, offs[i], dw, dh)
            tp += 80
        out[tp : tp + 2] = b"\x00\x00"

    p = layout_off
    opcodes_used = []
    for item, off_val in zip(layout_items, item_offs):
        kind = item["kind"]
        if kind == "static":
            struct.pack_into("<BBHHIHH", out, p, 0x01, 0x00, item["x"], item["y"], off_val, item["w"], item["h"])
            p += 14
            opcodes_used.append(0x00)
        elif kind == "anim":
            cnt = len(off_val)
            struct.pack_into("<BBBBBBBHHHH", out, p, 0x01, 0x2E, 0x00, cnt, 0x00, 0x01,
                             item["interval"], item["x"], item["y"], item["w"], item["h"])
            p += 15
            for fo in off_val:
                struct.pack_into("<I", out, p, fo)
                p += 4
            opcodes_used.append(0x2E)
        elif kind == "clock":
            dt = item["dt"]
            out[p : p + 6] = bytes([0x01, 0x02, dt, dt, dt, dt])
            for idx, (cx, cy) in enumerate(item["coords"]):
                struct.pack_into("<HH", out, p + 6 + idx * 4, cx, cy)
            if off_val:
                struct.pack_into("<HHIHH", out, p + 22, item["colon_x"], item["colon_y"], off_val, item["colon_w"], item["colon_h"])
            p += 34
            opcodes_used.append(0x02)
        elif kind == "two_digit":
            op, dt = item["op"], item["dt"]
            (x1, y1), (x2, y2) = item["coords"]
            struct.pack_into("<BBBBHHHH", out, p, 0x01, op, dt, dt, x1, y1, x2, y2)
            p += 12
            opcodes_used.append(op)
        elif kind == "weekday":
            struct.pack_into("<BBBHH", out, p, 0x01, 0x04, 0x01, item["x"], item["y"])
            p += 7
            for fo in off_val:
                struct.pack_into("<IHH", out, p, fo, item["w"], item["h"])
                p += 8
            opcodes_used.append(0x04)
        elif kind == "native_battery_bar":
            struct.pack_into("<BBHHIHHBBBBB", out, p, 0x01, 0x05, item["x"], item["y"], off_val,
                             item["w"], item["h"], item["pad_x"], item["pad_y"], item["fill_w"], item["fill_h"], item["style_byte"])
            p += 19
            opcodes_used.append(0x05)
        elif kind == "progress":
            struct.pack_into("<BBBBHH", out, p, 0x01, 0x12, item["sub"], len(off_val), item["x"], item["y"])
            p += 8
            for fo in off_val:
                struct.pack_into("<IHH", out, p, fo, item["w"], item["h"])
                p += 8
            opcodes_used.append(0x12)
        elif kind == "dash_glyph":
            struct.pack_into("<BBIHH", out, p, 0x01, 0x23, off_val, item["w"], item["h"])
            p += 10
            opcodes_used.append(0x23)
        elif kind == "heart_rate":
            struct.pack_into("<BBBBHH", out, p, 0x01, 0x06, item["dt"], item["align"], item["x"], item["y"])
            p += 26
            opcodes_used.append(0x06)
        elif kind == "steps":
            struct.pack_into("<BBBBHH", out, p, 0x01, 0x07, item["dt"], item["align"], item["x"], item["y"])
            p += 26
            opcodes_used.append(0x07)
        elif kind == "calories":
            struct.pack_into("<BBBBHH", out, p, 0x01, 0x09, item["dt"], item["align"], item["x"], item["y"])
            p += 17
            opcodes_used.append(0x09)
        elif kind == "distance":
            struct.pack_into("<BBBBHH", out, p, 0x01, 0x08, item["dt"], item["align"], item["x"], item["y"])
            struct.pack_into("<IHHH", out, p + 32, off_val, item["dot_w"], item["dot_h"], 0)
            p += 42
            opcodes_used.append(0x08)
        elif kind == "battery_pct":
            struct.pack_into("<BBBBHH", out, p, 0x01, 0x15, item["dt"], item["align"], item["x"], item["y"])
            p += 8
            opcodes_used.append(0x15)
        elif kind == "hand":
            struct.pack_into("<BBBHHIHHHH", out, p, 0x01, 0x0A, item["hid"], item["x"], item["y"],
                             off_val, item["w"], item["h"], 233, 233)
            p += 19
            opcodes_used.append(0x0A)
        elif kind == "month_name":
            struct.pack_into("<BBHH", out, p, 0x01, 0x0E, item["x"], item["y"])
            for idx, fo in enumerate(off_val[:12]):
                struct.pack_into("<IHH", out, p + 6 + idx * 8, fo, item["w"], item["h"])
            p += 198
            opcodes_used.append(0x0E)
        elif kind == "year":
            dt = item["dt"]
            out[p : p + 7] = bytes([0x01, 0x10, 0x04, dt, dt, dt, dt])
            for idx, (yx, yy) in enumerate(item["coords"][:4]):
                struct.pack_into("<HH", out, p + 7 + idx * 4, yx, yy)
            p += 23
            opcodes_used.append(0x10)
        elif kind == "ampm":
            x, y, w, h = item["x"], item["y"], item["w"], item["h"]
            struct.pack_into("<BBBHHHH", out, p, 0x01, 0x11, 0x01, x, y, x, y)
            struct.pack_into("<IHH", out, p + 11, off_val[0], w, h)
            struct.pack_into("<IHH", out, p + 19, off_val[1], w, h)
            p += 27
            opcodes_used.append(0x11)
        elif kind == "bluetooth":
            x, y, w, h = item["x"], item["y"], item["w"], item["h"]
            struct.pack_into("<BBBHH", out, p, 0x01, 0x14, 0x00, x, y)
            struct.pack_into("<IHH", out, p + 7, off_val[0], w, h)
            struct.pack_into("<IHH", out, p + 15, off_val[1], w, h)
            p += 23
            opcodes_used.append(0x14)
        elif kind == "tap_switch":
            struct.pack_into("<BBBBHH", out, p, 0x01, 0x1A, 0x00, len(off_val), item["x"], item["y"])
            p += 8
            for fo in off_val:
                struct.pack_into("<IHH", out, p, fo, item["w"], item["h"])
                p += 8
            opcodes_used.append(0x1A)
        elif kind == "weather_icon":
            struct.pack_into("<BBBHH", out, p, 0x01, 0x1B, len(off_val), item["x"], item["y"])
            p += 7
            for fo in off_val:
                struct.pack_into("<IHH", out, p, fo, item["w"], item["h"])
                p += 8
            opcodes_used.append(0x1B)
        elif kind == "temperature":
            struct.pack_into("<BBBBHH", out, p, 0x01, 0x1C, item["dt"], item["align"], item["x"], item["y"])
            struct.pack_into("<IHH", out, p + 8, off_val[0], item["minus_w"], item["minus_h"])
            struct.pack_into("<IHH", out, p + 16, off_val[1], item["degc_w"], item["degc_h"])
            struct.pack_into("<IHH", out, p + 24, off_val[2], item["degf_w"], item["degf_h"])
            p += 32
            opcodes_used.append(0x1C)
        elif kind == "dist_unit":
            x, y, w, h = item["x"], item["y"], item["w"], item["h"]
            struct.pack_into("<BBHH", out, p, 0x01, 0x1F, x, y)
            struct.pack_into("<IHH", out, p + 6, off_val[0], w, h)
            struct.pack_into("<IHH", out, p + 14, off_val[1], w, h)
            p += 22
            opcodes_used.append(0x1F)

    out[p : p + 2] = b"\x00\x00"

    fmt_flags = max(opcodes_used) if opcodes_used else 0x0002
    if fmt_flags < 0x0002:
        fmt_flags = 0x0002
    struct.pack_into("<HHIHHHH", out, 0x00, fmt_flags, 0xFFFF, prev_off, PREV_W, PREV_H, dt_off, layout_off)
    return bytes(out)


def compile_config_to_bin(config, out_bin_path, save_preview_path=None):
    """Compile a multi-layer Z-ordered watchface config into a hardware-verified Watch 4S `.bin` file."""
    preview_full = render_config_preview(config)
    if save_preview_path:
        os.makedirs(os.path.dirname(os.path.abspath(save_preview_path)), exist_ok=True)
        preview_full.save(save_preview_path)
    prev_img = preview_full.resize((PREV_W, PREV_H), Image.Resampling.LANCZOS)
    prev_blob = encode_image_rle_argb565(prev_img)

    bg_cfg = config.get("background", {})
    anim_specs = normalize_anim_sprites(config)
    gauges_list = [g for g in normalize_gauges(config) if g.get("enabled", True)]
    overlays_list = [o for o in (config.get("overlays") or []) if isinstance(o, dict) and o.get("enabled", True)]
    texts_list = [t for t in (config.get("text_labels") or []) if isinstance(t, dict) and t.get("enabled", True)]

    def assemble_pass(posterize_bits=None, anim_frame_cap=None):
        digit_tables = []

        def add_digit_table(sprites):
            tid = len(digit_tables)
            digit_tables.append([(encode_image_rle_argb565(s), s.width, s.height) for s in sprites])
            return tid

        # Build reusable items by ID
        anim_built = {}
        for sp in anim_specs:
            cap = min(anim_frame_cap, int(sp.get("frames", 8))) if anim_frame_cap else None
            frs, rect, iv, _ = extract_animated_frames(sp, override_count=cap, posterize_bits=posterize_bits)
            if len(frs) >= 2:
                anim_built[sp["id"]] = (frs, rect, iv, sp.get("is_bg_anim", False))

        ts_x, ts_y, ts_frames = build_tap_switch_assets(config.get("tap_switch", {}), posterize_bits=posterize_bits)
        has_ts = len(ts_frames) >= 2

        full_bg_anim = ("bg_anim" in anim_built and anim_built["bg_anim"][1][2] >= W and anim_built["bg_anim"][1][3] >= H)
        ts_op = float(config.get("tap_switch", {}).get("opacity", 100))
        ts_opaque = (ts_op >= 0.995 if 0.0 < ts_op <= 1.0 else ts_op >= 99.5)
        full_ts = (has_ts and ts_frames[0].width >= W and ts_frames[0].height >= H and ts_opaque)

        telem_cfg = config.get("telemetry", {})
        telem_assets = build_telemetry_assets(telem_cfg) if telem_cfg.get("enabled") else None
        has_telem = bool(telem_assets and (telem_assets["items"] or telem_assets["dist_unit"]))

        # Build static telemetry icon overlay sprite cleanly (so icons work above tap_switch / GIFs / bezels too!)
        telem_icons_sprite = None
        if telem_assets and telem_assets["show_icons"] and telem_assets["items"]:
            ic_canvas = _composite_telemetry_icons(Image.new("RGBA", (W, H), (0, 0, 0, 0)), telem_assets)
            ic_bb = ic_canvas.getbbox()
            if ic_bb:
                crop = ic_canvas.crop(ic_bb)
                telem_icons_sprite = (ic_bb[0], ic_bb[1], crop)

        gauges_map = {g.get("id", f"g{i+1}"): g for i, g in enumerate(gauges_list)}
        overlays_map = {o.get("id", f"ov{i+1}"): o for i, o in enumerate(overlays_list)}
        texts_map = {t.get("id", f"txt{i+1}"): t for i, t in enumerate(texts_list)}

        emitted_gauges, emitted_overlays, emitted_texts, emitted_anims = set(), set(), set(), set()
        layout_items = []
        has_dynamic_widget = False
        has_anim_hdr = False

        def emit_anim(aid):
            nonlocal has_anim_hdr, has_dynamic_widget
            if aid not in anim_built or aid in emitted_anims:
                return
            frs, rect, iv, _ = anim_built[aid]
            layout_items.append({
                "kind": "anim", "x": rect[0], "y": rect[1], "w": rect[2], "h": rect[3],
                "interval": iv, "blobs": [encode_image_rle_argb565(f) for f in frs],
            })
            emitted_anims.add(aid)
            has_anim_hdr = True
            has_dynamic_widget = True

        def emit_gauge(gid):
            nonlocal has_dynamic_widget
            if gid not in gauges_map or gid in emitted_gauges:
                return
            g = gauges_map[gid]
            if g.get("kind") == "native_battery_bar" or g.get("style") == "native_bar":
                nb = build_native_battery_bar(g)
                layout_items.append({
                    "kind": "native_battery_bar",
                    "x": nb["x"], "y": nb["y"], "w": nb["w"], "h": nb["h"],
                    "pad_x": nb["pad_x"], "pad_y": nb["pad_y"],
                    "fill_w": nb["fill_w"], "fill_h": nb["fill_h"], "style_byte": nb["style_byte"],
                    "blob": encode_image_rle_argb565(nb["sprite"]),
                })
            else:
                bx, by, bframes = build_battery_widget(g)
                metric_sub = PROGRESS_METRIC_SUB.get(g.get("metric", "battery"), 0x06)
                layout_items.append({
                    "kind": "progress", "sub": metric_sub,
                    "x": bx, "y": by, "w": bframes[0].width, "h": bframes[0].height,
                    "blobs": [encode_image_rle_argb565(f) for f in bframes],
                })
            emitted_gauges.add(gid)
            has_dynamic_widget = True

        def emit_overlay(oid):
            if oid not in overlays_map or oid in emitted_overlays:
                return
            ov = build_overlay_sprite(overlays_map[oid])
            if ov:
                layout_items.append({
                    "kind": "static", "x": ov["x"], "y": ov["y"], "w": ov["w"], "h": ov["h"],
                    "blob": encode_image_rle_argb565(ov["sprite"]),
                })
            emitted_overlays.add(oid)

        def emit_text(tid):
            if tid not in texts_map or tid in emitted_texts:
                return
            lb = build_text_label_sprite(texts_map[tid])
            if lb:
                layout_items.append({
                    "kind": "static", "x": lb["x"], "y": lb["y"], "w": lb["w"], "h": lb["h"],
                    "blob": encode_image_rle_argb565(lb["sprite"]),
                })
            emitted_texts.add(tid)

        order = resolve_layer_order(config)
        for token in order:
            if token == "background":
                if not full_bg_anim and not full_ts:
                    bg_img = _build_solid_gradient_bg(bg_cfg) if bg_cfg.get("mode") == "animated_gif" else build_background(bg_cfg)
                    layout_items.append({
                        "kind": "static", "x": 0, "y": 0, "w": W, "h": H,
                        "blob": encode_image_rle_argb565(bg_img),
                    })
                elif full_ts and not full_bg_anim:
                    # Emit a minimal ~4 KB pure-black 466x466 static base beneath full-screen `01 1a`
                    # (matches official `01 1a` dial structure where `01 00` precedes `01 1a`).
                    black_base = _build_solid_gradient_bg({"color": "#000000", "color2": "#000000"})
                    layout_items.append({
                        "kind": "static", "x": 0, "y": 0, "w": W, "h": H,
                        "blob": encode_image_rle_argb565(black_base),
                    })
                if "bg_anim" in anim_built and "anim:bg_anim" not in order:
                    emit_anim("bg_anim")

            elif token == "tap_switch":
                if has_ts:
                    layout_items.append({
                        "kind": "tap_switch", "x": ts_x, "y": ts_y,
                        "w": ts_frames[0].width, "h": ts_frames[0].height,
                        "blobs": [encode_image_rle_argb565(f) for f in ts_frames],
                    })
                    has_anim_hdr = True
                    has_dynamic_widget = True

            elif token == "bezel":
                bz = build_bezel_layer(config.get("bezel", {}))
                if bz is not None:
                    bb = bz.getbbox()
                    if bb:
                        crop = bz.crop(bb)
                        layout_items.append({
                            "kind": "static", "x": bb[0], "y": bb[1], "w": crop.width, "h": crop.height,
                            "blob": encode_image_rle_argb565(crop),
                        })

            elif token == "anim_sprites":
                for aid in list(anim_built.keys()):
                    emit_anim(aid)
            elif token.startswith("anim:"):
                emit_anim(token.split(":", 1)[1])

            elif token == "gauges":
                for gid in list(gauges_map.keys()):
                    emit_gauge(gid)
            elif token.startswith("gauge:"):
                emit_gauge(token.split(":", 1)[1])

            elif token == "overlays":
                for oid in list(overlays_map.keys()):
                    emit_overlay(oid)
            elif token.startswith("overlay:"):
                emit_overlay(token.split(":", 1)[1])

            elif token == "text_labels":
                for tid in list(texts_map.keys()):
                    emit_text(tid)
            elif token.startswith("text:"):
                emit_text(token.split(":", 1)[1])

            elif token == "weather":
                wa = build_weather_assets(config.get("weather", {}))
                if wa:
                    if wa["icon"]:
                        ic = wa["icon"]
                        layout_items.append({
                            "kind": "weather_icon", "x": ic["x"], "y": ic["y"], "w": ic["w"], "h": ic["h"],
                            "blobs": [encode_image_rle_argb565(f) for f in ic["frames"]],
                        })
                        has_dynamic_widget = True
                    if wa["temp"]:
                        tp = wa["temp"]
                        tdt = add_digit_table(tp["digits"])
                        layout_items.append({
                            "kind": "temperature", "dt": tdt, "align": tp["align"], "x": tp["x"], "y": tp["y"],
                            "minus_w": tp["minus"].width, "minus_h": tp["minus"].height,
                            "minus_blob": encode_image_rle_argb565(tp["minus"]),
                            "degc_w": tp["degc"].width, "degc_h": tp["degc"].height,
                            "degc_blob": encode_image_rle_argb565(tp["degc"]),
                            "degf_w": tp["degf"].width, "degf_h": tp["degf"].height,
                            "degf_blob": encode_image_rle_argb565(tp["degf"]),
                        })
                        has_dynamic_widget = True

            elif token == "bluetooth":
                bt = build_bluetooth_assets(config.get("bluetooth", {}))
                if bt:
                    layout_items.append({
                        "kind": "bluetooth", "x": bt["x"], "y": bt["y"], "w": bt["w"], "h": bt["h"],
                        "blob0": encode_image_rle_argb565(bt["disconnected"]),
                        "blob1": encode_image_rle_argb565(bt["connected"]),
                    })
                    has_dynamic_widget = True

            elif token == "weekday":
                wk_cfg = config.get("weekday", {})
                if wk_cfg.get("enabled"):
                    wx, wy, wframes = build_weekday_widget(wk_cfg)
                    layout_items.append({
                        "kind": "weekday", "x": wx, "y": wy, "w": wframes[0].width, "h": wframes[0].height,
                        "blobs": [encode_image_rle_argb565(f) for f in wframes],
                    })
                    has_dynamic_widget = True

            elif token == "date":
                date_cfg = config.get("date", {})
                if date_cfg.get("enabled"):
                    da = build_date_assets(date_cfg)
                    date_dt = None
                    if da["month_coords"] or da["day_coords"]:
                        date_dt = add_digit_table(da["digits"])
                    if da["month_name"]:
                        mn = da["month_name"]
                        layout_items.append({
                            "kind": "month_name", "x": mn["x"], "y": mn["y"], "w": mn["w"], "h": mn["h"],
                            "blobs": [encode_image_rle_argb565(f) for f in mn["frames"]],
                        })
                    if da["month_coords"]:
                        layout_items.append({"kind": "two_digit", "op": 0x0F, "dt": date_dt, "coords": da["month_coords"]})
                    if da["sep"]:
                        sx, sy, ssp = da["sep"]
                        layout_items.append({
                            "kind": "static", "x": sx, "y": sy, "w": ssp.width, "h": ssp.height,
                            "blob": encode_image_rle_argb565(ssp),
                        })
                    if da["day_coords"]:
                        layout_items.append({"kind": "two_digit", "op": 0x0D, "dt": date_dt, "coords": da["day_coords"]})
                    if da["year"]:
                        yr = da["year"]
                        yr_dt = add_digit_table(yr["digits"])
                        layout_items.append({"kind": "year", "dt": yr_dt, "coords": yr["coords"]})
                    has_dynamic_widget = True

            elif token == "clock":
                clk_cfg = config.get("digital_clock", {})
                if clk_cfg.get("enabled"):
                    c_digits, c_coords, c_wh, colon_info = build_digital_clock_assets(clk_cfg)
                    clk_dt = add_digit_table(c_digits)
                    clk_item = {"kind": "clock", "dt": clk_dt, "coords": c_coords, "colon_blob": None}
                    if colon_info:
                        col_x, col_y, col_sp = colon_info
                        clk_item.update({
                            "colon_x": col_x, "colon_y": col_y,
                            "colon_w": col_sp.width, "colon_h": col_sp.height,
                            "colon_blob": encode_image_rle_argb565(col_sp),
                        })
                    layout_items.append(clk_item)
                    if clk_cfg.get("show_seconds"):
                        s_digits, s_coords, _ = build_seconds_assets(clk_cfg, c_coords, c_wh)
                        sec_dt = add_digit_table(s_digits)
                        layout_items.append({"kind": "two_digit", "op": 0x18, "dt": sec_dt, "coords": s_coords})
                    ampm = build_ampm_assets(clk_cfg, c_coords, c_wh)
                    if ampm:
                        layout_items.append({
                            "kind": "ampm", "x": ampm["x"], "y": ampm["y"], "w": ampm["w"], "h": ampm["h"],
                            "blob0": encode_image_rle_argb565(ampm["am"]),
                            "blob1": encode_image_rle_argb565(ampm["pm"]),
                        })
                    has_dynamic_widget = True

            elif token == "telemetry":
                if has_telem:
                    if telem_icons_sprite is not None:
                        ix, iy, isp = telem_icons_sprite
                        layout_items.append({
                            "kind": "static", "x": ix, "y": iy, "w": isp.width, "h": isp.height,
                            "blob": encode_image_rle_argb565(isp),
                        })
                    if telem_assets["items"]:
                        telem_dt = add_digit_table(telem_assets["digits"])
                        dash_sp = telem_assets["dash"]
                        dot_sp = telem_assets["dot"]
                        for item in telem_assets["items"]:
                            k = item["key"]
                            if k == "heart_rate":
                                layout_items.append({
                                    "kind": "dash_glyph", "w": dash_sp.width, "h": dash_sp.height,
                                    "blob": encode_image_rle_argb565(dash_sp),
                                })
                                layout_items.append({"kind": "heart_rate", "dt": telem_dt, "align": item["align"], "x": item["x"], "y": item["y"]})
                            elif k == "steps":
                                layout_items.append({"kind": "steps", "dt": telem_dt, "align": item["align"], "x": item["x"], "y": item["y"]})
                            elif k == "calories":
                                layout_items.append({"kind": "calories", "dt": telem_dt, "align": item["align"], "x": item["x"], "y": item["y"]})
                            elif k == "distance":
                                layout_items.append({
                                    "kind": "distance", "dt": telem_dt, "align": item["align"], "x": item["x"], "y": item["y"],
                                    "dot_w": dot_sp.width, "dot_h": dot_sp.height, "dot_blob": encode_image_rle_argb565(dot_sp),
                                })
                            elif k == "battery_pct":
                                layout_items.append({"kind": "battery_pct", "dt": telem_dt, "align": item["align"], "x": item["x"], "y": item["y"]})
                    if telem_assets["dist_unit"]:
                        du = telem_assets["dist_unit"]
                        layout_items.append({
                            "kind": "dist_unit", "x": du["x"], "y": du["y"], "w": du["w"], "h": du["h"],
                            "blob0": encode_image_rle_argb565(du["km"]),
                            "blob1": encode_image_rle_argb565(du["mi"]),
                        })
                    has_dynamic_widget = True

            elif token == "hands":
                hand_cfg = config.get("analog_hands", {})
                if hand_cfg.get("enabled"):
                    hands, cap_img = build_analog_hands(hand_cfg)
                    for hid, hx, hy, himg in hands:
                        layout_items.append({
                            "kind": "hand", "hid": hid, "x": hx, "y": hy,
                            "w": himg.width, "h": himg.height,
                            "blob": encode_image_rle_argb565(himg),
                        })
                    if cap_img is not None:
                        layout_items.append({
                            "kind": "static",
                            "x": CX - cap_img.width // 2, "y": CY - cap_img.height // 2,
                            "w": cap_img.width, "h": cap_img.height,
                            "blob": encode_image_rle_argb565(cap_img),
                        })
                    has_dynamic_widget = True

        # Pure image mode (no dynamic widgets at all): attach invisible dummy clock so Watch 4S accepts pure artwork
        if not has_dynamic_widget:
            blank = Image.new("RGBA", (46, 71), (0, 0, 0, 0))
            b_blob = encode_image_rle_argb565(blank)
            clk_dt = len(digit_tables)
            digit_tables.append([(b_blob, 46, 71) for _ in range(10)])
            layout_items.append({
                "kind": "clock", "dt": clk_dt,
                "coords": [(105, 344), (167, 344), (253, 344), (315, 344)],
                "colon_blob": None,
            })

        # Official Watch 4S (LS26) invariant (211/211 verified): whenever the 8-byte animation
        # prefix (`00 02 00 00 00 02 01 00`) is emitted at 0x10 (for `01 1a` or `01 2e`),
        # at least one digit table (`DT#0`) is always present before `00 00` terminator.
        if has_anim_hdr and len(digit_tables) == 0:
            tiny_blank = Image.new("RGBA", (4, 4), (0, 0, 0, 0))
            tiny_blob = encode_image_rle_argb565(tiny_blank)
            digit_tables.append([(tiny_blob, 4, 4) for _ in range(10)])

        return _pack_watchface_binary(
            has_anim_header=has_anim_hdr,
            digit_tables=digit_tables,
            layout_items=layout_items,
            prev_blob=prev_blob,
        )

    raw_bin = assemble_pass()

    # Auto-optimize multi-frame sprites/tap-switch if > 1.3 MB Watch 4S flash budget
    if len(raw_bin) > MAX_WATCH_BIN_BYTES:
        for bits in (5, 4):
            cand = assemble_pass(posterize_bits=bits)
            if len(cand) <= MAX_WATCH_BIN_BYTES:
                raw_bin = cand
                break
        if len(raw_bin) > MAX_WATCH_BIN_BYTES and anim_specs:
            max_f = max(int(s.get("frames", 8)) for s in anim_specs)
            while max_f > 2 and len(raw_bin) > MAX_WATCH_BIN_BYTES:
                max_f = max(2, max_f - 2)
                raw_bin = assemble_pass(posterize_bits=4, anim_frame_cap=max_f)

    os.makedirs(os.path.dirname(os.path.abspath(out_bin_path)), exist_ok=True)
    with open(out_bin_path, "wb") as f:
        f.write(raw_bin)
    return out_bin_path


# --------------------------------------------------------------------------- #
# Binary Validator & Preview Decoder
# --------------------------------------------------------------------------- #

def inspect_watchface_bin(raw_or_path):
    """
    Parse and validate any Haylou Watch 4S `.bin` using the 210/210 verified LS26 binary spec.
    Returns dict(valid, flags, preview_off, dt_off, lo_off, has_anim_header, digit_tables, opcodes, size_bytes, errors).
    """
    if isinstance(raw_or_path, (bytes, bytearray)):
        raw = bytes(raw_or_path)
    else:
        with open(raw_or_path, "rb") as f:
            raw = f.read()

    errors = []
    if len(raw) < 16:
        return {"valid": False, "errors": ["File smaller than 16-byte header"], "size_bytes": len(raw)}

    flags, magic, prev_off, pw, ph, dt_off, lo_off = struct.unpack_from("<HHIHHHH", raw, 0)
    if magic != 0xFFFF:
        errors.append(f"Bad magic: 0x{magic:04x}")
    if prev_off >= len(raw) or pw == 0 or ph == 0:
        errors.append(f"Invalid preview header: off=0x{prev_off:x} {pw}x{ph}")
    if lo_off >= len(raw):
        errors.append(f"Layout offset out of bounds: 0x{lo_off:x}")

    has_anim_header = False
    dt_count = 0
    if dt_off:
        tp = dt_off
        if raw[tp : tp + 8] == ANIM_RESOURCE_PREFIX:
            has_anim_header = True
            tp += 8
        while tp + 2 <= lo_off:
            if raw[tp : tp + 2] == b"\x00\x00":
                tp += 2
                break
            if raw[tp : tp + 2] == b"\x01\x01":
                dt_count += 1
                tp += 83
            else:
                errors.append(f"Unexpected resource table bytes at 0x{tp:x}: {raw[tp:tp+8].hex(' ')}")
                break

    opcodes = []
    p = lo_off
    end = min(prev_off, len(raw))
    terminated = False
    while p + 2 <= end:
        if raw[p : p + 2] == b"\x00\x00":
            terminated = True
            break
        if raw[p] != 0x01:
            errors.append(f"Non-0x01 opcode byte at 0x{p:x}: {raw[p:p+16].hex(' ')}")
            break
        op = raw[p + 1]
        if op == 0x00:
            p += 14
        elif op == 0x02:
            p += 34
        elif op == 0x04:
            sub = raw[p + 2]
            p += 7 + (14 if sub == 0x02 else 7) * 8
        elif op == 0x05:
            p += 19
        elif op in (0x06, 0x07):
            p += 26
        elif op == 0x08:
            p += 42
        elif op == 0x09:
            p += 17
        elif op == 0x0A:
            p += 19
        elif op in (0x0D, 0x0F, 0x18):
            p += 12
        elif op == 0x0E:
            p += 6 + 24 * 8
        elif op == 0x10:
            n = raw[p + 2]
            p += 3 + n + n * 4
        elif op == 0x11:
            p += 27
        elif op == 0x12:
            cnt = raw[p + 3]
            p += 8 + cnt * 8
        elif op == 0x14:
            p += 23
        elif op == 0x15:
            p += 8
        elif op == 0x1A:
            cnt = raw[p + 3]
            p += 8 + cnt * 8
        elif op == 0x1B:
            cnt = raw[p + 2]
            p += 7 + cnt * 8
        elif op == 0x1C:
            p += 32
        elif op == 0x1D:
            p += 3
        elif op == 0x1F:
            p += 22
        elif op == 0x23:
            p += 10
        elif op == 0x25:
            p += 26
        elif op == 0x2E:
            cnt = raw[p + 3]
            p += 15 + cnt * 4
        else:
            errors.append(f"Unknown opcode 01 {op:02x} at 0x{p:x}")
            break
        opcodes.append(f"01 {op:02x}")

    if has_anim_header and dt_count == 0:
        errors.append("Animation header present at 0x10 with 0 digit tables (Watch 4S requires dt_cnt >= 1)")

    if not terminated:
        errors.append("Layout stream did not reach 00 00 terminator")

    return {
        "valid": len(errors) == 0,
        "flags": flags,
        "preview_off": prev_off,
        "dt_off": dt_off,
        "lo_off": lo_off,
        "has_anim_header": has_anim_header,
        "digit_tables": dt_count,
        "opcodes": opcodes,
        "size_bytes": len(raw),
        "within_flash_budget": len(raw) <= MAX_WATCH_BIN_BYTES,
        "errors": errors,
    }


def decode_bin_preview(bin_path):
    """Extract the 280x280 ARGB565-RLE preview image from any Haylou Watch 4S .bin file."""
    with open(bin_path, "rb") as f:
        data = f.read()
    _, _, prev_off, pw, ph = struct.unpack_from("<HHIHH", data, 0)
    if pw == 0 or ph == 0 or prev_off >= len(data):
        raise ValueError("Invalid Watch 4S .bin header")
    img = Image.new("RGBA", (pw, ph), (0, 0, 0, 0))
    px = img.load()
    for y in range(ph):
        entry = struct.unpack_from("<I", data, prev_off + y * 4)[0]
        row_off = prev_off + (entry & 0x1FFFFF)
        row_len = entry >> 21
        p = row_off
        end = row_off + row_len
        x = 0
        while p < end and x < pw:
            c = data[p]
            p += 1
            if c & 0x80:
                cnt = c & 0x7F
                a, hi, lo = data[p], data[p + 1], data[p + 2]
                p += 3
                val = (hi << 8) | lo
                r = ((val >> 11) & 0x1F) * 255 // 31
                g = ((val >> 5) & 0x3F) * 255 // 63
                b = (val & 0x1F) * 255 // 31
                for _ in range(cnt):
                    if x < pw:
                        px[x, y] = (r, g, b, a)
                        x += 1
            else:
                for _ in range(c):
                    a, hi, lo = data[p], data[p + 1], data[p + 2]
                    p += 3
                    val = (hi << 8) | lo
                    r = ((val >> 11) & 0x1F) * 255 // 31
                    g = ((val >> 5) & 0x3F) * 255 // 63
                    b = (val & 0x1F) * 255 // 31
                    if x < pw:
                        px[x, y] = (r, g, b, a)
                        x += 1
    return img.resize((W, H), Image.Resampling.LANCZOS)
