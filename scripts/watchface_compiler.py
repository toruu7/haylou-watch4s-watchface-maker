"""
Haylou Watch 4S (LS26) — Unified Multi-Layer Watchface Compiler & Renderer

Hardware-verified against all 210 official Haylou Watch 4S (LS26001) cloud dials.
Compiles any combination of:
  - Background: Custom Image, Solid/Gradient, Ben 10 Omnitrix, or Native Animated GIF/WebP (`01 2e`)
  - Digital Clock (`01 02`, 34 B with optional native blinking colon) + Live Seconds (`01 18`)
  - Live Date (`01 0f` Month MM + `01 0d` Day DD + optional `/` or `-` separator)
  - Live Health Telemetry:
      * Steps (`01 07`, 26 B)
      * Heart Rate BPM (`01 23` dash glyph + `01 06`, 26 B)
      * Calories Kcal (`01 09`, 17 B)
      * Distance km/mi (`01 08`, 42 B with decimal dot sprite)
      * Battery % Number (`01 15`, 8 B)
  - Multi-Frame Progress Gauge (`01 12`: Battery `0x06`, Steps `0x00`, Calories `0x02`, Distance `0x03`)
  - Weekday (`01 04`, 7-frame SUN..SAT)
  - Analog Hands (`01 0a`, 19 B each + optional center cap)
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

# Mandatory 8-byte resource table prefix emitted at 0x10 whenever 01 2e / 01 1a animations are used
ANIM_RESOURCE_PREFIX = bytes.fromhex("0002000000020100")


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

    c1 = hex_to_rgb(color)
    sc = hex_to_rgb(stroke_color)

    if glow_radius > 0:
        gc = hex_to_rgb(glow_color or color)
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
        c2 = hex_to_rgb(color2)
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
    """Lightly quantize RGB channels (preserving alpha) so busy GIF frames RLE-compress much tighter."""
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


def extract_animated_frames(bg_cfg, override_count=None, posterize_bits=None):
    """
    Extract evenly-spaced RGBA frames from an animated GIF/WebP for Watch 4S `01 2e` playback.
    Returns (frames_list, (x, y, w, h), hardware_interval, frame_duration_ms).
    """
    img_path = bg_cfg.get("image_path")
    if not img_path or not os.path.isfile(img_path):
        return [], (0, 0, W, H), 15, 250

    max_frames = max(2, min(20, int(override_count or bg_cfg.get("anim_frames", 8))))
    fps = max(1.0, min(15.0, float(bg_cfg.get("anim_fps", 4))))
    anim_size = max(120, min(W, int(bg_cfg.get("anim_size", W))))
    # Even dimensions avoid any sub-pixel centering drift
    anim_size = anim_size & ~1
    circular = bool(bg_cfg.get("anim_circular", True))
    brightness = float(bg_cfg.get("brightness", 100))
    vignette = float(bg_cfg.get("vignette", 0)) if anim_size >= W else 0.0

    ax = max(0, min(W - anim_size, int(bg_cfg.get("anim_x", CX)) - anim_size // 2))
    ay = max(0, min(H - anim_size, int(bg_cfg.get("anim_y", CY)) - anim_size // 2))

    raw_frames = []
    durations = []
    with Image.open(img_path) as im:
        n = getattr(im, "n_frames", 1)
        if n <= 1:
            raw_frames = [im.convert("RGBA")]
            durations = [250]
        else:
            # Sample evenly across all source frames
            count = min(n, max_frames)
            indices = sorted(set(int(round(i * (n - 1) / max(1, count - 1))) for i in range(count)))
            idx_set = set(indices)
            for idx, frame in enumerate(ImageSequence.Iterator(im)):
                if idx in idx_set:
                    raw_frames.append(frame.convert("RGBA"))
                    durations.append(int(frame.info.get("duration", 120) or 120))

    processed = []
    for fr in raw_frames:
        sq = _prepare_circular_pil(fr, anim_size, circular=circular)
        sq = apply_amoled_dimmer(sq, brightness, vignette)
        if posterize_bits:
            sq = _posterize_for_rle(sq, bits=posterize_bits)
        processed.append(sq)

    # Hardware Watch 4S `01 2e` interval: 15 matches Star Scales (~4 fps), 24 matches Christmas Vibe (~2.5 fps)
    hw_interval = max(4, min(60, int(round(60.0 / fps))))
    preview_ms = max(65, int(round(1000.0 / fps)))
    return processed, (ax, ay, anim_size, anim_size), hw_interval, preview_ms


def _build_solid_gradient_bg(bg_cfg):
    brightness = float(bg_cfg.get("brightness", 100))
    vignette = float(bg_cfg.get("vignette", 0))
    c1 = hex_to_rgb(bg_cfg.get("color", "#0b0e14"))
    c2 = hex_to_rgb(bg_cfg.get("color2", bg_cfg.get("color", "#0b0e14")))
    img = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    for y in range(H):
        t = y / max(1, H - 1)
        r = int(c1[0] + (c2[0] - c1[0]) * t)
        g = int(c1[1] + (c2[1] - c1[1]) * t)
        b = int(c1[2] + (c2[2] - c1[2]) * t)
        d.line([(0, y), (W, y)], fill=(r, g, b, 255))
    mask = Image.new("L", (W, H), 0)
    ImageDraw.Draw(mask).ellipse((0, 0, W - 1, H - 1), fill=255)
    out = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    out.paste(img, (0, 0), mask)
    return apply_amoled_dimmer(out, brightness, vignette)


def build_background(bg_cfg):
    mode = bg_cfg.get("mode", "solid")
    brightness = float(bg_cfg.get("brightness", 100))
    vignette = float(bg_cfg.get("vignette", 0))
    if mode == "animated_gif":
        # Static backdrop behind animated overlay (or first frame if full-screen)
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
        # Guard against styles that only exist in newer omnitrix_watchface_maker builds
        if style not in ("alien_force", "os", "omniverse", "5yl"):
            style = "alien_force"
        img = draw_omnitrix_bg(style=style, palette=pal, show_ticks=ticks, glow_strength=glow)
        return apply_amoled_dimmer(img, brightness, vignette)
    return _build_solid_gradient_bg(bg_cfg)


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
        # Place neatly to the right of M0 if room, otherwise centered just below clock
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


def build_date_assets(date_cfg):
    """
    Build live Date assets for formats: 'MM/DD', 'DD/MM', 'MM-DD', 'DD-MM', 'DD'.
    Returns dict with digits, (dw, dh), month_coords (or None), day_coords, sep_info (or None).
    """
    fmt = date_cfg.get("format", "MM/DD").upper()
    font_size = max(14, min(52, int(date_cfg.get("font_size", 24))))
    stroke_w = max(0, int(date_cfg.get("stroke_width", 1)))
    color = date_cfg.get("color", "#FFFFFF")
    stroke_col = date_cfg.get("stroke_color", "#000000")

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

    if fmt == "DD":
        total_w = dw * 2 + gap
        x0 = max(0, min(W - total_w, cx - total_w // 2))
        return {
            "digits": digits,
            "wh": (dw, dh),
            "month_coords": None,
            "day_coords": [(x0, y0), (x0 + dw + gap, y0)],
            "sep": None,
            "format": fmt,
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
        "digits": digits,
        "wh": (dw, dh),
        "month_coords": month_coords,
        "day_coords": day_coords,
        "sep": (sep_x, y0, sep_sprite),
        "format": fmt,
    }


def _draw_mini_icon(kind, size, color_rgb):
    """Draw a crisp vector mini-icon (flame, heart, steps, pin, bolt) onto a (size, size) RGBA sprite."""
    s = max(14, int(size))
    S = 2
    im = Image.new("RGBA", (s * S, s * S), (0, 0, 0, 0))
    d = ImageDraw.Draw(im)
    c = (*color_rgb, 255)
    w = s * S
    h = s * S

    if kind == "heart_rate":
        # Smooth heart polygon
        d.ellipse((int(w * 0.10), int(h * 0.14), int(w * 0.54), int(h * 0.58)), fill=c)
        d.ellipse((int(w * 0.46), int(h * 0.14), int(w * 0.90), int(h * 0.58)), fill=c)
        d.polygon([(int(w * 0.12), int(h * 0.40)), (int(w * 0.88), int(h * 0.40)), (w // 2, int(h * 0.90))], fill=c)
    elif kind == "calories":
        # Stylized flame
        d.polygon([
            (w // 2, int(h * 0.06)),
            (int(w * 0.78), int(h * 0.42)),
            (int(w * 0.84), int(h * 0.68)),
            (int(w * 0.68), int(h * 0.92)),
            (int(w * 0.32), int(h * 0.92)),
            (int(w * 0.16), int(h * 0.68)),
            (int(w * 0.26), int(h * 0.42)),
        ], fill=c)
        inner = (min(255, color_rgb[0] + 70), min(255, color_rgb[1] + 70), min(255, color_rgb[2] + 70), 255)
        d.ellipse((int(w * 0.36), int(h * 0.56), int(w * 0.64), int(h * 0.86)), fill=inner)
    elif kind == "steps":
        # Two angled footprints
        d.ellipse((int(w * 0.14), int(h * 0.12), int(w * 0.44), int(h * 0.58)), fill=c)
        d.ellipse((int(w * 0.20), int(h * 0.62), int(w * 0.40), int(h * 0.82)), fill=c)
        d.ellipse((int(w * 0.56), int(h * 0.24), int(w * 0.86), int(h * 0.70)), fill=c)
        d.ellipse((int(w * 0.60), int(h * 0.74), int(w * 0.80), int(h * 0.94)), fill=c)
    elif kind == "distance":
        # Map pin
        d.ellipse((int(w * 0.20), int(h * 0.08), int(w * 0.80), int(h * 0.66)), fill=c)
        d.polygon([(int(w * 0.24), int(h * 0.48)), (int(w * 0.76), int(h * 0.48)), (w // 2, int(h * 0.94))], fill=c)
        d.ellipse((int(w * 0.38), int(h * 0.24), int(w * 0.62), int(h * 0.48)), fill=(0, 0, 0, 220))
    else:
        # Lightning bolt for battery_pct
        d.polygon([
            (int(w * 0.58), int(h * 0.06)),
            (int(w * 0.20), int(h * 0.54)),
            (int(w * 0.48), int(h * 0.54)),
            (int(w * 0.40), int(h * 0.94)),
            (int(w * 0.80), int(h * 0.44)),
            (int(w * 0.52), int(h * 0.44)),
        ], fill=c)
    return im.resize((s, s), Image.Resampling.LANCZOS)


def build_telemetry_assets(telem_cfg):
    """Build shared digit set, HR dash glyph, Distance dot glyph, and active metric descriptors."""
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
        dtmp.text((dtx, dty), ".", font=font, fill=(*hex_to_rgb(stroke_col), 255), stroke_width=stroke_w, stroke_fill=(*hex_to_rgb(stroke_col), 255))
    dtmp.text((dtx, dty), ".", font=font, fill=(*hex_to_rgb(color), 255))

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
    for key, (dx, dy, sample, icon_col) in metric_defaults.items():
        sub = telem_cfg.get(key)
        if not isinstance(sub, dict) or not sub.get("enabled"):
            continue
        x = max(0, min(W - 1, int(sub.get("x", dx))))
        y = max(0, min(H - dh, int(sub.get("y", dy))))
        align = int(sub.get("align", default_align))
        if align not in (0, 1, 2):
            align = default_align
        items.append({
            "key": key,
            "x": x,
            "y": y,
            "align": align,
            "sample": sample,
            "icon_color": hex_to_rgb(sub.get("icon_color")) if sub.get("icon_color") else icon_col,
        })

    return {
        "digits": digits,
        "wh": (dw, dh),
        "dash": dash_sprite,
        "dot": dot_sprite,
        "items": items,
        "show_icons": bool(telem_cfg.get("show_icons", True)),
    }


def _paste_aligned_number(comp, text, digits, dot_sprite, x, y, align, dw, dh):
    """Render a preview number using exact Watch 4S alignment: 0=Left, 1=Right, 2=Center."""
    sprites = [dot_sprite if ch == "." else digits[int(ch)] for ch in text if ch == "." or ch.isdigit()]
    total_w = sum(s.width for s in sprites)
    if align == 1:  # Right
        cur_x = x - total_w
    elif align == 2:  # Center
        cur_x = x - total_w // 2
    else:  # 0 = Left
        cur_x = x
    for sp in sprites:
        px = max(0, min(W - sp.width, int(cur_x)))
        py = max(0, min(H - sp.height, int(y)))
        comp.paste(sp, (px, py), sp)
        cur_x += sp.width
    return cur_x - total_w, total_w


def _composite_telemetry_icons(bg_rgba, telem_assets):
    """Optionally bake crisp mini icons onto the background beside each enabled telemetry readout."""
    if not telem_assets["show_icons"] or not telem_assets["items"]:
        return bg_rgba
    out = bg_rgba.copy()
    dw, dh = telem_assets["wh"]
    icon_sz = max(14, min(28, int(dh * 0.82)))
    for item in telem_assets["items"]:
        icon = _draw_mini_icon(item["key"], icon_sz, item["icon_color"])
        # Place icon nicely above centered widgets or to the left of left-aligned widgets
        if item["align"] == 0:  # Left
            ix = max(6, item["x"] - icon_sz - 6)
            iy = max(6, min(H - icon_sz - 6, item["y"] + (dh - icon_sz) // 2))
        elif item["align"] == 1:  # Right
            ix = min(W - icon_sz - 6, item["x"] + 6)
            iy = max(6, min(H - icon_sz - 6, item["y"] + (dh - icon_sz) // 2))
        else:  # Center -> place icon centered just above the readout
            ix = max(6, min(W - icon_sz - 6, item["x"] - icon_sz // 2))
            iy = max(6, item["y"] - icon_sz - 4)
        out.paste(icon, (ix, iy), icon)
    return out


def build_analog_hands(hand_cfg):
    style = hand_cfg.get("style", "omnitrix")
    prim_hex = hand_cfg.get("color", "#39FF14")
    accent_hex = hand_cfg.get("accent_color", "#FFFFFF")
    show_sec = bool(hand_cfg.get("show_seconds", True))
    center_cap = bool(hand_cfg.get("center_cap", style != "omnitrix"))

    prim = hex_to_rgb(prim_hex)
    accent = hex_to_rgb(accent_hex)

    if style == "omnitrix":
        pal = palette_from_hex(prim_hex, accent_hex)
        hands = draw_omnitrix_hands(pal)
    elif style == "neon":
        hands = []
        specs = [
            (0, 26, 130, 6, prim),
            (1, 22, 182, 4, accent),
            (2, 18, 206, 2, prim),
        ]
        for hid, sw, sh, lw, col in specs:
            img = Image.new("RGBA", (sw, sh), (0, 0, 0, 0))
            d = ImageDraw.Draw(img)
            d.line([(sw // 2, 10), (sw // 2, sh - 4)], fill=(*col, 255), width=lw)
            glow = img.filter(ImageFilter.GaussianBlur(radius=4))
            img = Image.alpha_composite(glow, img)
            hands.append((hid, CX - sw // 2, CY - sh, img))
    elif style == "minimal":
        hands = []
        specs = [
            (0, 18, 128, 5, accent),
            (1, 14, 180, 4, accent),
            (2, 10, 206, 2, prim),
        ]
        for hid, sw, sh, r, col in specs:
            img = Image.new("RGBA", (sw, sh), (0, 0, 0, 0))
            d = ImageDraw.Draw(img)
            d.rounded_rectangle((sw // 2 - r, 4, sw // 2 + r, sh - 2), radius=r, fill=(*col, 255))
            hands.append((hid, CX - sw // 2, CY - sh, img))
    else:
        hands = []
        hw, hh = 26, 136
        hi = Image.new("RGBA", (hw, hh), (0, 0, 0, 0))
        hd = ImageDraw.Draw(hi)
        hd.polygon(
            [(hw // 2, 4), (hw - 4, hh - 10), (hw // 2, hh), (4, hh - 10)],
            fill=(*accent, 255),
            outline=(15, 18, 22, 255),
        )
        hd.line([(hw // 2, 18), (hw // 2, hh - 18)], fill=(*prim, 255), width=4)
        hands.append((0, CX - hw // 2, CY - hh + 12, hi))

        mw, mh = 22, 190
        mi = Image.new("RGBA", (mw, mh), (0, 0, 0, 0))
        md = ImageDraw.Draw(mi)
        md.polygon(
            [(mw // 2, 4), (mw - 4, mh - 10), (mw // 2, mh), (4, mh - 10)],
            fill=(*accent, 255),
            outline=(15, 18, 22, 255),
        )
        md.line([(mw // 2, 18), (mw // 2, mh - 18)], fill=(*prim, 255), width=3)
        hands.append((1, CX - mw // 2, CY - mh + 12, mi))

        sw, sh = 12, 215
        si = Image.new("RGBA", (sw, sh), (0, 0, 0, 0))
        sd = ImageDraw.Draw(si)
        sd.line([(sw // 2, 4), (sw // 2, sh)], fill=(*prim, 255), width=3)
        hands.append((2, CX - sw // 2, CY - sh + 20, si))

    if not show_sec:
        hands = [h for h in hands if h[0] != 2]

    cap_img = None
    if center_cap:
        cap_size = 24
        cap_img = Image.new("RGBA", (cap_size, cap_size), (0, 0, 0, 0))
        cd = ImageDraw.Draw(cap_img)
        cd.ellipse((1, 1, cap_size - 2, cap_size - 2), fill=(25, 30, 36, 255), outline=(*accent, 255), width=2)
        cd.ellipse((7, 7, cap_size - 8, cap_size - 8), fill=(*prim, 255))

    return hands, cap_img


def build_battery_widget(batt_cfg):
    """Build 11-frame progress gauge (0%, 10%, ..., 100%) for Battery, Steps, Calories, or Distance."""
    style = batt_cfg.get("style", "ring")
    col_rgb = hex_to_rgb(batt_cfg.get("color", "#39FF14"))
    thickness = max(3, min(14, int(batt_cfg.get("thickness", 6))))
    metric = batt_cfg.get("metric", "battery")
    low_red = (metric == "battery")
    frames = []

    if style == "ring":
        bbox = (4, 4, W - 5, H - 5)
        for step in range(11):
            img = Image.new("RGBA", (W, H), (0, 0, 0, 0))
            if step > 0:
                d = ImageDraw.Draw(img)
                d.arc(bbox, start=-90, end=270, fill=(28, 34, 38, 170), width=thickness)
                sweep = int(360 * step / 10)
                c = (255, 45, 45, 255) if (low_red and step <= 2) else (*col_rgb, 255)
                d.arc(bbox, start=-90, end=-90 + sweep, fill=c, width=thickness)
            frames.append(img)
        return 0, 0, frames

    if style == "arc":
        bbox = (14, 14, W - 15, H - 15)
        for step in range(11):
            img = Image.new("RGBA", (W, H), (0, 0, 0, 0))
            d = ImageDraw.Draw(img)
            d.arc(bbox, start=35, end=145, fill=(35, 42, 50, 190), width=thickness + 2)
            if step > 0:
                sweep = int(110 * step / 10)
                c = (255, 45, 45, 255) if (low_red and step <= 2) else (*col_rgb, 255)
                d.arc(bbox, start=145 - sweep, end=145, fill=c, width=thickness + 2)
            frames.append(img)
        return 0, 0, frames

    if style == "bar":
        bw, bh = 120, max(12, thickness + 8)
        bx = max(0, min(W - bw, int(batt_cfg.get("x", 233)) - bw // 2))
        by = max(0, min(H - bh, int(batt_cfg.get("y", 405)) - bh // 2))
        for step in range(11):
            img = Image.new("RGBA", (bw, bh), (0, 0, 0, 0))
            d = ImageDraw.Draw(img)
            d.rounded_rectangle(
                (0, 0, bw - 1, bh - 1),
                radius=bh // 2,
                fill=(20, 25, 32, 210),
                outline=(90, 105, 120, 220),
                width=2,
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
        d.rounded_rectangle(
            (1, 2, bw - 8, bh - 3),
            radius=6,
            fill=(15, 20, 25, 210),
            outline=(220, 230, 240, 235),
            width=2,
        )
        d.rounded_rectangle((bw - 6, 8, bw - 2, bh - 9), radius=2, fill=(220, 230, 240, 235))
        if step > 0:
            fw = max(4, int((bw - 15) * step / 10))
            c = (255, 45, 45, 255) if (low_red and step <= 2) else (*col_rgb, 255)
            d.rounded_rectangle((5, 6, 5 + fw, bh - 7), radius=3, fill=c)
        frames.append(img)
    return bx, by, frames


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
            lbl,
            ww,
            wh,
            font,
            color=wk_cfg.get("color", "#FFFFFF"),
            stroke_width=stroke_w,
            stroke_color=wk_cfg.get("stroke_color", "#000000"),
        )
        for lbl in labels
    ]
    wx = max(0, min(W - ww, int(wk_cfg.get("x", 233)) - ww // 2))
    wy = max(0, min(H - wh, int(wk_cfg.get("y", 95)) - wh // 2))
    return wx, wy, frames


def _render_foreground_layers(base_rgba, config, sec_val=35, blink_on=True):
    """Composite all enabled widgets onto a 466x466 RGBA background image for preview rendering."""
    comp = base_rgba.copy()

    telem_cfg = config.get("telemetry", {})
    telem_assets = None
    if telem_cfg.get("enabled"):
        telem_assets = build_telemetry_assets(telem_cfg)
        if telem_assets["items"]:
            comp = _composite_telemetry_icons(comp, telem_assets)

    batt_cfg = config.get("battery", {})
    if batt_cfg.get("enabled"):
        bx, by, bframes = build_battery_widget(batt_cfg)
        comp.paste(bframes[8], (bx, by), bframes[8])

    wk_cfg = config.get("weekday", {})
    if wk_cfg.get("enabled"):
        wx, wy, wframes = build_weekday_widget(wk_cfg)
        comp.paste(wframes[3], (wx, wy), wframes[3])  # WED

    date_cfg = config.get("date", {})
    if date_cfg.get("enabled"):
        da = build_date_assets(date_cfg)
        if da["month_coords"]:
            for dv, (dx, dy) in zip([1, 1], da["month_coords"]):
                comp.paste(da["digits"][dv], (dx, dy), da["digits"][dv])
        if da["sep"]:
            sx, sy, ssp = da["sep"]
            comp.paste(ssp, (sx, sy), ssp)
        for dv, (dx, dy) in zip([2, 4], da["day_coords"]):
            comp.paste(da["digits"][dv], (dx, dy), da["digits"][dv])

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

    if telem_assets and telem_assets["items"]:
        dw, dh = telem_assets["wh"]
        for item in telem_assets["items"]:
            _paste_aligned_number(
                comp,
                item["sample"],
                telem_assets["digits"],
                telem_assets["dot"],
                item["x"],
                item["y"],
                item["align"],
                dw,
                dh,
            )

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

    return comp


def render_config_preview(config):
    """Render an exact 466x466 RGBA static preview of any multi-layer watchface config."""
    bg = build_background(config.get("background", {}))
    return _render_foreground_layers(bg, config)


def render_config_animated_preview(config):
    """
    If config uses an animated GIF background, return (list_of_466x466_RGBA_frames, duration_ms).
    Otherwise return (None, 0).
    """
    bg_cfg = config.get("background", {})
    if bg_cfg.get("mode") != "animated_gif":
        return None, 0
    frames, (ax, ay, aw, ah), _, dur_ms = extract_animated_frames(bg_cfg)
    if len(frames) < 2:
        return None, 0
    backdrop = _build_solid_gradient_bg(bg_cfg) if aw < W else None
    out_frames = []
    for idx, fr in enumerate(frames):
        if backdrop is not None:
            base = backdrop.copy()
            base.paste(fr, (ax, ay), fr)
        else:
            base = fr
        out_frames.append(_render_foreground_layers(base, config, sec_val=(35 + idx) % 60, blink_on=(idx % 2 == 0)))
    return out_frames, dur_ms


def _pack_watchface_binary(
    *,
    bg_blob,
    anim_entry,
    digit_tables,
    layout_items,
    prev_blob,
):
    """
    Assemble a complete Watch 4S `.bin` byte buffer from pre-encoded RLE blobs.
    `digit_tables`: list of ([(blob, w, h) x 10])
    `anim_entry`: None or dict(frames=[blobs], x, y, w, h, interval)
    """
    has_anim = anim_entry is not None
    has_tables = has_anim or len(digit_tables) > 0

    # 1. Compute Resource/Digit Table section (0x10 .. layout_off)
    dt_off = 0x0010 if has_tables else 0x0000
    table_len = 0
    if has_anim:
        table_len += len(ANIM_RESOURCE_PREFIX)  # 8 bytes: 00 02 00 00 00 02 01 00
    table_len += len(digit_tables) * 83  # 3 + 10*8 bytes per digit table
    if has_tables:
        table_len += 2  # 00 00 terminator
    layout_off = (0x0010 + table_len) if has_tables else 0x0010

    # 2. Compute Layout Stream length (layout_off .. data_start)
    layout_size = 0
    for item in layout_items:
        kind = item["kind"]
        if kind == "static":
            layout_size += 14
        elif kind == "anim":
            layout_size += 15 + len(item["blobs"]) * 4
        elif kind == "clock":
            layout_size += 34
        elif kind == "two_digit":  # 01 0d / 01 0f / 01 18
            layout_size += 12
        elif kind == "weekday":
            layout_size += 7 + len(item["blobs"]) * 8
        elif kind == "progress":
            layout_size += 8 + len(item["blobs"]) * 8
        elif kind == "dash_glyph":  # 01 23
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
    layout_size += 2  # 00 00 terminator

    # Match classic 0x98 alignment for simple 1-table static+clock dials
    header_total = layout_off + layout_size
    img_start = (header_total + 3) & ~3
    if not has_anim and len(digit_tables) == 1 and len(layout_items) == 2 and layout_items[1]["kind"] == "clock":
        img_start = max(0x98, img_start)

    out = bytearray(img_start)

    # 3. Append all RLE sprite blobs (4-byte aligned with 0xFF padding)
    def append_blob(blob):
        off = len(out)
        out.extend(blob)
        pad4_ff(out)
        return off

    # Background / Static / Anim / Widget blobs in layout order
    item_offs = []
    for item in layout_items:
        kind = item["kind"]
        if kind == "static":
            item_offs.append(append_blob(item["blob"]))
        elif kind == "anim":
            item_offs.append([append_blob(b) for b in item["blobs"]])
        elif kind == "clock":
            col_blob = item.get("colon_blob")
            item_offs.append(append_blob(col_blob) if col_blob is not None else 0)
        elif kind in ("weekday", "progress"):
            item_offs.append([append_blob(b) for b in item["blobs"]])
        elif kind == "dash_glyph":
            item_offs.append(append_blob(item["blob"]))
        elif kind == "distance":
            item_offs.append(append_blob(item["dot_blob"]))
        elif kind == "hand":
            item_offs.append(append_blob(item["blob"]))
        else:
            item_offs.append(None)

    # Digit table blobs
    dt_offs = []
    for tbl in digit_tables:
        dt_offs.append([append_blob(blob) for blob, _, _ in tbl])

    # Preview image last
    prev_off = append_blob(prev_blob)

    # 4. Write Resource / Digit Table section
    if has_tables:
        tp = 0x10
        if has_anim:
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

    # 5. Write Layout Stream & track max opcode ID for header.flags
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
            struct.pack_into(
                "<BBBBBBBHHHH",
                out,
                p,
                0x01,
                0x2E,
                0x00,
                cnt,
                0x00,
                0x01,
                item["interval"],
                item["x"],
                item["y"],
                item["w"],
                item["h"],
            )
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
                struct.pack_into(
                    "<HHIHH", out, p + 22, item["colon_x"], item["colon_y"], off_val, item["colon_w"], item["colon_h"]
                )
            p += 34
            opcodes_used.append(0x02)
        elif kind == "two_digit":
            op = item["op"]
            dt = item["dt"]
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
            struct.pack_into(
                "<BBBHHIHHHH",
                out,
                p,
                0x01,
                0x0A,
                item["hid"],
                item["x"],
                item["y"],
                off_val,
                item["w"],
                item["h"],
                233,
                233,
            )
            p += 19
            opcodes_used.append(0x0A)

    out[p : p + 2] = b"\x00\x00"

    # 6. Write 16-Byte Main Header (flags = highest layout opcode ID, min 0x0002)
    fmt_flags = max(opcodes_used) if opcodes_used else 0x0002
    if fmt_flags < 0x0002:
        fmt_flags = 0x0002
    struct.pack_into("<HHIHHHH", out, 0x00, fmt_flags, 0xFFFF, prev_off, PREV_W, PREV_H, dt_off, layout_off)
    return bytes(out)


def compile_config_to_bin(config, out_bin_path, save_preview_path=None):
    """Compile a multi-layer watchface config into a hardware-verified Watch 4S `.bin` file."""
    bg_cfg = config.get("background", {})
    bg_mode = bg_cfg.get("mode", "solid")

    clk_cfg = config.get("digital_clock", {})
    has_clock = bool(clk_cfg.get("enabled"))
    has_seconds = has_clock and bool(clk_cfg.get("show_seconds"))

    date_cfg = config.get("date", {})
    has_date = bool(date_cfg.get("enabled"))

    telem_cfg = config.get("telemetry", {})
    telem_assets = build_telemetry_assets(telem_cfg) if telem_cfg.get("enabled") else None
    has_telem = bool(telem_assets and telem_assets["items"])

    batt_cfg = config.get("battery", {})
    has_batt = bool(batt_cfg.get("enabled"))

    wk_cfg = config.get("weekday", {})
    has_wk = bool(wk_cfg.get("enabled"))

    hand_cfg = config.get("analog_hands", {})
    has_hands = bool(hand_cfg.get("enabled"))

    # Check if background is an animated GIF/WebP
    anim_frames = []
    anim_rect = (0, 0, W, H)
    anim_interval = 15
    if bg_mode == "animated_gif":
        anim_frames, anim_rect, anim_interval, _ = extract_animated_frames(bg_cfg)
    has_anim = len(anim_frames) >= 2

    pure_image_mode = not (has_clock or has_date or has_telem or has_batt or has_wk or has_hands or has_anim)

    # Render static preview & save optional PNG
    preview_full = render_config_preview(config)
    if save_preview_path:
        os.makedirs(os.path.dirname(os.path.abspath(save_preview_path)), exist_ok=True)
        preview_full.save(save_preview_path)
    prev_img = preview_full.resize((PREV_W, PREV_H), Image.Resampling.LANCZOS)
    prev_blob = encode_image_rle_argb565(prev_img)

    # Multi-digit-table pool
    digit_tables = []

    def add_digit_table(sprites):
        tid = len(digit_tables)
        digit_tables.append([(encode_image_rle_argb565(s), s.width, s.height) for s in sprites])
        return tid

    # Build static background (with optional telemetry mini-icons baked cleanly into static backdrop)
    use_static_bg = True
    if has_anim and anim_rect[2] >= W and anim_rect[3] >= H:
        # Full-screen 466x466 animated GIF replaces static 01 00 background (matches official Christmas Vibe!)
        use_static_bg = False
        if has_telem and telem_assets["show_icons"]:
            anim_frames = [_composite_telemetry_icons(fr, telem_assets) for fr in anim_frames]
    else:
        bg_img = _build_solid_gradient_bg(bg_cfg) if has_anim else build_background(bg_cfg)
        if has_telem:
            bg_img = _composite_telemetry_icons(bg_img, telem_assets)
        bg_blob = encode_image_rle_argb565(bg_img)

    # Build non-anim widget assets once
    post_bg_items = []

    if has_batt:
        bx, by, bframes = build_battery_widget(batt_cfg)
        metric_sub = PROGRESS_METRIC_SUB.get(batt_cfg.get("metric", "battery"), 0x06)
        post_bg_items.append({
            "kind": "progress",
            "sub": metric_sub,
            "x": bx,
            "y": by,
            "w": bframes[0].width,
            "h": bframes[0].height,
            "blobs": [encode_image_rle_argb565(f) for f in bframes],
        })

    if has_wk:
        wx, wy, wframes = build_weekday_widget(wk_cfg)
        post_bg_items.append({
            "kind": "weekday",
            "x": wx,
            "y": wy,
            "w": wframes[0].width,
            "h": wframes[0].height,
            "blobs": [encode_image_rle_argb565(f) for f in wframes],
        })

    if has_date:
        da = build_date_assets(date_cfg)
        date_dt = add_digit_table(da["digits"])
        if da["month_coords"]:
            post_bg_items.append({"kind": "two_digit", "op": 0x0F, "dt": date_dt, "coords": da["month_coords"]})
        if da["sep"]:
            sx, sy, ssp = da["sep"]
            post_bg_items.append({
                "kind": "static",
                "x": sx,
                "y": sy,
                "w": ssp.width,
                "h": ssp.height,
                "blob": encode_image_rle_argb565(ssp),
            })
        post_bg_items.append({"kind": "two_digit", "op": 0x0D, "dt": date_dt, "coords": da["day_coords"]})

    if pure_image_mode:
        blank = Image.new("RGBA", (46, 71), (0, 0, 0, 0))
        b_blob = encode_image_rle_argb565(blank)
        clk_dt = len(digit_tables)
        digit_tables.append([(b_blob, 46, 71) for _ in range(10)])
        post_bg_items.append({
            "kind": "clock",
            "dt": clk_dt,
            "coords": [(105, 344), (167, 344), (253, 344), (315, 344)],
            "colon_blob": None,
        })
    elif has_clock:
        c_digits, c_coords, c_wh, colon_info = build_digital_clock_assets(clk_cfg)
        clk_dt = add_digit_table(c_digits)
        clk_item = {"kind": "clock", "dt": clk_dt, "coords": c_coords, "colon_blob": None}
        if colon_info:
            col_x, col_y, col_sp = colon_info
            clk_item.update({
                "colon_x": col_x,
                "colon_y": col_y,
                "colon_w": col_sp.width,
                "colon_h": col_sp.height,
                "colon_blob": encode_image_rle_argb565(col_sp),
            })
        post_bg_items.append(clk_item)
        if has_seconds:
            s_digits, s_coords, _ = build_seconds_assets(clk_cfg, c_coords, c_wh)
            sec_dt = add_digit_table(s_digits)
            post_bg_items.append({"kind": "two_digit", "op": 0x18, "dt": sec_dt, "coords": s_coords})

    if has_telem:
        telem_dt = add_digit_table(telem_assets["digits"])
        dash_sp = telem_assets["dash"]
        dot_sp = telem_assets["dot"]
        for item in telem_assets["items"]:
            k = item["key"]
            if k == "heart_rate":
                post_bg_items.append({
                    "kind": "dash_glyph",
                    "w": dash_sp.width,
                    "h": dash_sp.height,
                    "blob": encode_image_rle_argb565(dash_sp),
                })
                post_bg_items.append({
                    "kind": "heart_rate",
                    "dt": telem_dt,
                    "align": item["align"],
                    "x": item["x"],
                    "y": item["y"],
                })
            elif k == "steps":
                post_bg_items.append({
                    "kind": "steps",
                    "dt": telem_dt,
                    "align": item["align"],
                    "x": item["x"],
                    "y": item["y"],
                })
            elif k == "calories":
                post_bg_items.append({
                    "kind": "calories",
                    "dt": telem_dt,
                    "align": item["align"],
                    "x": item["x"],
                    "y": item["y"],
                })
            elif k == "distance":
                post_bg_items.append({
                    "kind": "distance",
                    "dt": telem_dt,
                    "align": item["align"],
                    "x": item["x"],
                    "y": item["y"],
                    "dot_w": dot_sp.width,
                    "dot_h": dot_sp.height,
                    "dot_blob": encode_image_rle_argb565(dot_sp),
                })
            elif k == "battery_pct":
                post_bg_items.append({
                    "kind": "battery_pct",
                    "dt": telem_dt,
                    "align": item["align"],
                    "x": item["x"],
                    "y": item["y"],
                })

    if has_hands:
        hands, cap_img = build_analog_hands(hand_cfg)
        for hid, hx, hy, himg in hands:
            post_bg_items.append({
                "kind": "hand",
                "hid": hid,
                "x": hx,
                "y": hy,
                "w": himg.width,
                "h": himg.height,
                "blob": encode_image_rle_argb565(himg),
            })
        if cap_img is not None:
            post_bg_items.append({
                "kind": "static",
                "x": CX - cap_img.width // 2,
                "y": CY - cap_img.height // 2,
                "w": cap_img.width,
                "h": cap_img.height,
                "blob": encode_image_rle_argb565(cap_img),
            })

    # Assemble binary; if animated GIF exceeds Watch 4S flash budget (~1.3 MB), auto-optimize RLE / frame count
    def build_with_anim(frames_to_use):
        items = []
        if use_static_bg:
            items.append({"kind": "static", "x": 0, "y": 0, "w": W, "h": H, "blob": bg_blob})
        anim_obj = None
        if has_anim and frames_to_use:
            anim_blobs = [encode_image_rle_argb565(f) for f in frames_to_use]
            anim_obj = {
                "kind": "anim",
                "x": anim_rect[0],
                "y": anim_rect[1],
                "w": anim_rect[2],
                "h": anim_rect[3],
                "interval": anim_interval,
                "blobs": anim_blobs,
            }
            items.append(anim_obj)
        items.extend(post_bg_items)
        return _pack_watchface_binary(
            bg_blob=bg_blob if use_static_bg else None,
            anim_entry=anim_obj,
            digit_tables=digit_tables,
            layout_items=items,
            prev_blob=prev_blob,
        )

    raw_bin = build_with_anim(anim_frames)

    if has_anim and len(raw_bin) > MAX_WATCH_BIN_BYTES:
        # Pass 1: gently snap RGB565 bits (5-bit -> 4-bit) to boost RLE run compression dramatically
        for bits in (5, 4):
            q_frames = [_posterize_for_rle(f, bits=bits) for f in anim_frames]
            cand = build_with_anim(q_frames)
            if len(cand) <= MAX_WATCH_BIN_BYTES:
                raw_bin = cand
                break
        # Pass 2: if still over budget, trim frame count gracefully down to >= 2 frames
        if len(raw_bin) > MAX_WATCH_BIN_BYTES and len(anim_frames) > 2:
            cur_frames = [_posterize_for_rle(f, bits=4) for f in anim_frames]
            while len(cur_frames) > 2 and len(raw_bin) > MAX_WATCH_BIN_BYTES:
                target_n = max(2, len(cur_frames) - 2)
                idxs = [int(round(i * (len(cur_frames) - 1) / (target_n - 1))) for i in range(target_n)]
                cur_frames = [cur_frames[i] for i in idxs]
                raw_bin = build_with_anim(cur_frames)

    os.makedirs(os.path.dirname(os.path.abspath(out_bin_path)), exist_ok=True)
    with open(out_bin_path, "wb") as f:
        f.write(raw_bin)
    return out_bin_path


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
