"""
Haylou Watch 4S (LS26) — Unified Multi-Layer Watchface Compiler & Renderer (Phase A)
Compiles any combination of:
  - Background (Custom Image, Solid/Gradient, or Omnitrix OS/AF/Omniverse/5YL)
  - Digital Clock (Horizontal or Stacked Vertical, Custom TTF/OTF, Gradient, Outline, Glow)
  - Analog Hands (Omnitrix, Classic Needles, Neon Pointers, Minimal Baton + Center Cap)
  - Battery Widget (11-frame Outer Ring, Arc Gauge, Horizontal Bar, or Pill Icon)
  - Weekday Widget (7-frame SUN..SAT with Custom Font, Color & Outline)
into a native, 100% hardware-verified Watch 4S ARGB565-RLE .bin file.
"""

import math
import os
import struct
import sys
from PIL import Image, ImageDraw, ImageFilter, ImageFont

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
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


def load_font(font_path, size):
    if font_path and os.path.exists(font_path):
        try:
            return ImageFont.truetype(font_path, size)
        except Exception:
            pass
    for fallback in (r"C:\Windows\Fonts\arialbd.ttf", r"C:\Windows\Fonts\segoeuib.ttf"):
        if os.path.exists(fallback):
            return ImageFont.truetype(fallback, size)
    return ImageFont.load_default()


def render_styled_text_sprite(text, box_w, box_h, font, color="#FFFFFF", color2=None,
                              stroke_width=0, stroke_color="#000000",
                              glow_radius=0, glow_color=None):
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

    # 1. Optional neon outer glow
    if glow_radius > 0:
        gc = hex_to_rgb(glow_color or color)
        glow_layer = Image.new("RGBA", (box_w, box_h), (0, 0, 0, 0))
        gd = ImageDraw.Draw(glow_layer)
        gd.text((tx, ty), text, font=font, fill=(*gc, 255), stroke_width=max(1, stroke_width + 1), stroke_fill=(*gc, 255))
        glow_layer = glow_layer.filter(ImageFilter.GaussianBlur(radius=glow_radius))
        canvas = Image.alpha_composite(canvas, glow_layer)

    # 2. Optional stroke/outline behind fill
    if stroke_width > 0:
        stroke_layer = Image.new("RGBA", (box_w, box_h), (0, 0, 0, 0))
        sd = ImageDraw.Draw(stroke_layer)
        sd.text((tx, ty), text, font=font, fill=(*sc, 255), stroke_width=stroke_width, stroke_fill=(*sc, 255))
        canvas = Image.alpha_composite(canvas, stroke_layer)

    # 3. Fill (solid or vertical gradient)
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


def apply_amoled_dimmer(img_rgba, brightness_pct=100, vignette_pct=0):
    """
    Scale RGB pixel values to achieve true sub-hardware AMOLED dimming (15%..100%)
    and optional smooth radial dark edge vignette (0%..80%).
    """
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
        # Radial dark vignette mask near the circular bezel edge
        vig = Image.new("RGBA", (w, h), (0, 0, 0, 0))
        vd = ImageDraw.Draw(vig)
        cx, cy = w // 2, h // 2
        max_r = min(cx, cy)
        steps = 28
        for i in range(steps):
            t = i / (steps - 1)  # 0 inner -> 1 outer
            rad = int(max_r * (1.0 - 0.42 * (1.0 - t)))
            alpha = int(255 * v_strength * (t ** 1.8))
            vd.ellipse((cx - rad, cy - rad, cx + rad, cy + rad), outline=(0, 0, 0, alpha), width=max(2, max_r // steps + 1))
        # Clip vignette to existing alpha
        vig_clipped = Image.new("RGBA", (w, h), (0, 0, 0, 0))
        vig_clipped.paste(vig, (0, 0), a)
        out = Image.alpha_composite(out, vig_clipped)
    return out


def build_background(bg_cfg):
    mode = bg_cfg.get("mode", "solid")
    brightness = float(bg_cfg.get("brightness", 100))
    vignette = float(bg_cfg.get("vignette", 0))
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
        img = draw_omnitrix_bg(style=style, palette=pal, show_ticks=ticks, glow_strength=glow)
        return apply_amoled_dimmer(img, brightness, vignette)

    # Solid or vertical gradient round AMOLED background
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


def build_digital_clock_assets(clk_cfg):
    font_size = max(24, min(96, int(clk_cfg.get("font_size", 60))))
    font = load_font(clk_cfg.get("font_path"), font_size)
    stroke_w = int(clk_cfg.get("stroke_width", 0))
    glow_r = int(clk_cfg.get("glow_radius", 0))
    pad = stroke_w * 2 + glow_r * 2 + 8

    # Measure max digit box
    tmp = ImageDraw.Draw(Image.new("RGBA", (10, 10)))
    max_w, max_h = 30, 40
    for d in range(10):
        bb = tmp.textbbox((0, 0), str(d), font=font, stroke_width=stroke_w)
        max_w = max(max_w, bb[2] - bb[0])
        max_h = max(max_h, bb[3] - bb[1])
    dw = min(110, max_w + pad)
    dh = min(130, max_h + pad)

    digits = [
        render_styled_text_sprite(
            str(d), dw, dh, font,
            color=clk_cfg.get("color", "#FFFFFF"),
            color2=clk_cfg.get("color2") or None,
            stroke_width=stroke_w,
            stroke_color=clk_cfg.get("stroke_color", "#000000"),
            glow_radius=glow_r,
            glow_color=clk_cfg.get("glow_color") or None,
        )
        for d in range(10)
    ]

    cx = int(clk_cfg.get("x", 233))
    cy = int(clk_cfg.get("y", 233))
    layout = clk_cfg.get("layout", "horizontal")
    gap = int(clk_cfg.get("spacing", 6))

    if layout == "stacked":
        # HH on top row, MM on bottom row
        row_gap = max(4, gap)
        x_left = cx - dw - gap // 2
        x_right = cx + gap // 2
        y_top = cy - dh - row_gap // 2
        y_bot = cy + row_gap // 2
        coords = [(x_left, y_top), (x_right, y_top), (x_left, y_bot), (x_right, y_bot)]
    else:
        # Horizontal HH  MM
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

    # Clamp safely inside 466x466
    clamped = [(max(0, min(W - dw, int(x))), max(0, min(H - dh, int(y)))) for x, y in coords]
    return digits, clamped, (dw, dh)


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
        # Glowing thin cyberpunk neon pointers
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
        # Sleek modern baton hands
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
        # Classic tapered watch needles with dark outline & luminous center
        hands = []
        # Hour
        hw, hh = 26, 136
        hi = Image.new("RGBA", (hw, hh), (0, 0, 0, 0))
        hd = ImageDraw.Draw(hi)
        hd.polygon([(hw // 2, 4), (hw - 4, hh - 10), (hw // 2, hh), (4, hh - 10)], fill=(*accent, 255), outline=(15, 18, 22, 255))
        hd.line([(hw // 2, 18), (hw // 2, hh - 18)], fill=(*prim, 255), width=4)
        hands.append((0, CX - hw // 2, CY - hh + 12, hi))
        # Minute
        mw, mh = 22, 190
        mi = Image.new("RGBA", (mw, mh), (0, 0, 0, 0))
        md = ImageDraw.Draw(mi)
        md.polygon([(mw // 2, 4), (mw - 4, mh - 10), (mw // 2, mh), (4, mh - 10)], fill=(*accent, 255), outline=(15, 18, 22, 255))
        md.line([(mw // 2, 18), (mw // 2, mh - 18)], fill=(*prim, 255), width=3)
        hands.append((1, CX - mw // 2, CY - mh + 12, mi))
        # Second
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
    """Build 11-frame battery widget (0%, 10%, ..., 100%). Returns (x, y, frames)."""
    style = batt_cfg.get("style", "ring")
    col_rgb = hex_to_rgb(batt_cfg.get("color", "#39FF14"))
    thickness = max(3, min(14, int(batt_cfg.get("thickness", 6))))
    frames = []

    if style == "ring":
        bbox = (4, 4, W - 5, H - 5)
        for step in range(11):
            img = Image.new("RGBA", (W, H), (0, 0, 0, 0))
            if step > 0:
                d = ImageDraw.Draw(img)
                d.arc(bbox, start=-90, end=270, fill=(28, 34, 38, 170), width=thickness)
                sweep = int(360 * step / 10)
                c = (255, 45, 45, 255) if step <= 2 else (*col_rgb, 255)
                d.arc(bbox, start=-90, end=-90 + sweep, fill=c, width=thickness)
            frames.append(img)
        return 0, 0, frames

    if style == "arc":
        # Bottom curved arc gauge (120 degrees wide)
        bbox = (14, 14, W - 15, H - 15)
        for step in range(11):
            img = Image.new("RGBA", (W, H), (0, 0, 0, 0))
            d = ImageDraw.Draw(img)
            d.arc(bbox, start=35, end=145, fill=(35, 42, 50, 190), width=thickness + 2)
            if step > 0:
                sweep = int(110 * step / 10)
                c = (255, 45, 45, 255) if step <= 2 else (*col_rgb, 255)
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
            d.rounded_rectangle((0, 0, bw - 1, bh - 1), radius=bh // 2, fill=(20, 25, 32, 210), outline=(90, 105, 120, 220), width=2)
            if step > 0:
                fw = max(6, int((bw - 6) * step / 10))
                c = (255, 45, 45, 255) if step <= 2 else (*col_rgb, 255)
                d.rounded_rectangle((3, 3, 3 + fw, bh - 4), radius=(bh - 6) // 2, fill=c)
            frames.append(img)
        return bx, by, frames

    # Classic pill icon
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
            c = (255, 45, 45, 255) if step <= 2 else (*col_rgb, 255)
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


def render_config_preview(config):
    """Render an exact 466x466 RGBA preview of a multi-layer watchface config (10:10:35, 80% batt, WED)."""
    comp = build_background(config.get("background", {}))

    batt_cfg = config.get("battery", {})
    if batt_cfg.get("enabled"):
        bx, by, bframes = build_battery_widget(batt_cfg)
        comp.paste(bframes[8], (bx, by), bframes[8])

    wk_cfg = config.get("weekday", {})
    if wk_cfg.get("enabled"):
        wx, wy, wframes = build_weekday_widget(wk_cfg)
        comp.paste(wframes[3], (wx, wy), wframes[3])  # WED

    clk_cfg = config.get("digital_clock", {})
    if clk_cfg.get("enabled"):
        digits, coords, _ = build_digital_clock_assets(clk_cfg)
        for dval, (dx, dy) in zip([1, 0, 1, 0], coords):
            comp.paste(digits[dval], (dx, dy), digits[dval])

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


def compile_config_to_bin(config, out_bin_path, save_preview_path=None):
    """Compile multi-layer config into a native Haylou Watch 4S .bin file."""
    bg_img = build_background(config.get("background", {}))

    clk_cfg = config.get("digital_clock", {})
    has_clock = bool(clk_cfg.get("enabled"))
    batt_cfg = config.get("battery", {})
    has_batt = bool(batt_cfg.get("enabled"))
    wk_cfg = config.get("weekday", {})
    has_wk = bool(wk_cfg.get("enabled"))
    hand_cfg = config.get("analog_hands", {})
    has_hands = bool(hand_cfg.get("enabled"))

    # Pure image (no clock, no widgets, no hands) -> use official 0x0002 digital container with transparent digits
    pure_image_mode = not (has_clock or has_batt or has_wk or has_hands)

    # Render exact preview
    preview_full = render_config_preview(config)
    if save_preview_path:
        os.makedirs(os.path.dirname(os.path.abspath(save_preview_path)), exist_ok=True)
        preview_full.save(save_preview_path)
    prev_img = preview_full.resize((PREV_W, PREV_H), Image.Resampling.LANCZOS)

    # Prepare assets
    digit_blobs = []
    digit_wh = (46, 71)
    clock_coords = [(105, 344), (167, 344), (253, 344), (315, 344)]
    if pure_image_mode:
        blank = Image.new("RGBA", (46, 71), (0, 0, 0, 0))
        b_blob = encode_image_rle_argb565(blank)
        digit_blobs = [b_blob for _ in range(10)]
    elif has_clock:
        digits, clock_coords, digit_wh = build_digital_clock_assets(clk_cfg)
        digit_blobs = [encode_image_rle_argb565(d) for d in digits]

    bg_blob = encode_image_rle_argb565(bg_img)
    prev_blob = encode_image_rle_argb565(prev_img)

    batt_xy = (0, 0)
    batt_blobs, batt_wh = [], (W, H)
    if has_batt:
        bx, by, bframes = build_battery_widget(batt_cfg)
        batt_xy = (bx, by)
        batt_wh = (bframes[0].width, bframes[0].height)
        batt_blobs = [encode_image_rle_argb565(f) for f in bframes]

    wk_xy = (0, 0)
    wk_blobs, wk_wh = [], (0, 0)
    if has_wk:
        wx, wy, wframes = build_weekday_widget(wk_cfg)
        wk_xy = (wx, wy)
        wk_wh = (wframes[0].width, wframes[0].height)
        wk_blobs = [encode_image_rle_argb565(f) for f in wframes]

    hands_data = []
    cap_img, cap_blob = None, None
    if has_hands:
        hands, cap_img = build_analog_hands(hand_cfg)
        for hid, hx, hy, himg in hands:
            hands_data.append((hid, hx, hy, himg.width, himg.height, encode_image_rle_argb565(himg)))
        if cap_img is not None:
            cap_blob = encode_image_rle_argb565(cap_img)

    # Calculate header & layout stream sizes
    use_digit_table = pure_image_mode or has_clock
    digit_table_off = 0x0010 if use_digit_table else 0x0000
    layout_off = 0x0065 if use_digit_table else 0x0010

    # Layout stream size
    layout_size = 14  # Background (01 00)
    if use_digit_table:
        layout_size += 22  # Digital clock coords (01 02 + 4 zeros + 8 uint16 = 22 bytes)
    if has_batt:
        layout_size += 8 + 11 * 8
    if has_wk:
        layout_size += 7 + 7 * 8
    if has_hands:
        layout_size += len(hands_data) * 19
        if cap_blob is not None:
            layout_size += 14
    layout_size += 2  # 00 00 terminator

    # Match exact 0x98 alignment for simple digital-only faces
    header_total = layout_off + layout_size
    if use_digit_table and not (has_batt or has_wk or has_hands):
        img_start = max(0x98, (header_total + 3) & ~3)
    else:
        img_start = (header_total + 3) & ~3

    out = bytearray(img_start)

    # Append image blobs (all 4-byte aligned with 0xFF padding)
    bg_off = len(out); out.extend(bg_blob); pad4_ff(out)

    digit_offs = []
    for db in digit_blobs:
        digit_offs.append(len(out)); out.extend(db); pad4_ff(out)

    batt_offs = []
    for bb in batt_blobs:
        batt_offs.append(len(out)); out.extend(bb); pad4_ff(out)

    wk_offs = []
    for wb in wk_blobs:
        wk_offs.append(len(out)); out.extend(wb); pad4_ff(out)

    hand_offs = []
    for _, _, _, _, _, hb in hands_data:
        hand_offs.append(len(out)); out.extend(hb); pad4_ff(out)

    cap_off = 0
    if cap_blob is not None:
        cap_off = len(out); out.extend(cap_blob); pad4_ff(out)

    prev_off = len(out); out.extend(prev_blob); pad4_ff(out)

    # Write Main Header (0x00..0x0F)
    fmt_flags = 0x0012 if (has_batt or has_wk or has_hands) else 0x0002
    struct.pack_into('<HHIHHHH', out, 0x00, fmt_flags, 0xFFFF, prev_off, PREV_W, PREV_H, digit_table_off, layout_off)

    # Write Digit Table at 0x10 if used
    if use_digit_table:
        out[0x10:0x13] = bytes([0x01, 0x01, 0x00])
        for i in range(10):
            struct.pack_into('<IHH', out, 0x13 + i * 8, digit_offs[i], digit_wh[0], digit_wh[1])

    # Write Layout Stream at layout_off
    p = layout_off
    # 1. Background
    struct.pack_into('<BBHHIHH', out, p, 0x01, 0x00, 0, 0, bg_off, W, H)
    p += 14

    # 2. Battery
    if has_batt:
        struct.pack_into('<BBBBHH', out, p, 0x01, 0x12, 0x06, 11, batt_xy[0], batt_xy[1])
        p += 8
        for boff in batt_offs:
            struct.pack_into('<IHH', out, p, boff, batt_wh[0], batt_wh[1])
            p += 8

    # 3. Weekday
    if has_wk:
        struct.pack_into('<BBBHH', out, p, 0x01, 0x04, 0x01, wk_xy[0], wk_xy[1])
        p += 7
        for woff in wk_offs:
            struct.pack_into('<IHH', out, p, woff, wk_wh[0], wk_wh[1])
            p += 8

    # 4. Digital Clock
    if use_digit_table:
        out[p:p+6] = bytes([0x01, 0x02, 0x00, 0x00, 0x00, 0x00])
        p += 6
        for cx, cy in clock_coords:
            struct.pack_into('<HH', out, p, cx, cy)
            p += 4

    # 5. Analog Hands + Optional Cap
    if has_hands:
        for idx, (hid, hx, hy, hw, hh, _) in enumerate(hands_data):
            struct.pack_into('<BBBHHIHHI', out, p, 0x01, 0x0a, hid, hx, hy, hand_offs[idx], hw, hh, 0xFFFFFFFF)
            p += 19
        if cap_blob is not None:
            struct.pack_into('<BBHHIHH', out, p, 0x01, 0x00, CX - cap_img.width // 2, CY - cap_img.height // 2, cap_off, cap_img.width, cap_img.height)
            p += 14

    # 6. End terminator
    out[p:p+2] = b'\x00\x00'

    os.makedirs(os.path.dirname(os.path.abspath(out_bin_path)), exist_ok=True)
    with open(out_bin_path, 'wb') as f:
        f.write(out)
    return out_bin_path


def decode_bin_preview(bin_path):
    """Extract the 280x280 ARGB565-RLE preview image from any Haylou Watch 4S .bin file."""
    with open(bin_path, 'rb') as f:
        data = f.read()
    _, _, prev_off, pw, ph = struct.unpack_from('<HHIHH', data, 0)
    if pw == 0 or ph == 0 or prev_off >= len(data):
        raise ValueError("Invalid Watch 4S .bin header")
    img = Image.new("RGBA", (pw, ph), (0, 0, 0, 0))
    px = img.load()
    for y in range(ph):
        entry = struct.unpack_from('<I', data, prev_off + y * 4)[0]
        row_off = prev_off + (entry & 0x1FFFFF)
        row_len = entry >> 21
        p = row_off
        end = row_off + row_len
        x = 0
        while p < end and x < pw:
            c = data[p]; p += 1
            if c & 0x80:
                cnt = c & 0x7F
                a, hi, lo = data[p], data[p+1], data[p+2]; p += 3
                val = (hi << 8) | lo
                r = ((val >> 11) & 0x1F) * 255 // 31
                g = ((val >> 5) & 0x3F) * 255 // 63
                b = (val & 0x1F) * 255 // 31
                for _ in range(cnt):
                    if x < pw: px[x, y] = (r, g, b, a); x += 1
            else:
                for _ in range(c):
                    a, hi, lo = data[p], data[p+1], data[p+2]; p += 3
                    val = (hi << 8) | lo
                    r = ((val >> 11) & 0x1F) * 255 // 31
                    g = ((val >> 5) & 0x3F) * 255 // 63
                    b = (val & 0x1F) * 255 // 31
                    if x < pw: px[x, y] = (r, g, b, a); x += 1
    return img.resize((W, H), Image.Resampling.LANCZOS)
