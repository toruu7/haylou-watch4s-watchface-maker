"""
Haylou Watch 4S (LS26) - Ben 10 Omnitrix Watchface Generator (4 Styles + Custom Colors)
Supports:
  - alien_force : Ben 10 Alien Force / UAF
  - os          : Ben 10 Original Series
  - omniverse   : Ben 10 Omniverse
  - 5yl         : 5 Years Later
Plus 6 preset colorways OR any custom hex color + adjustable glow & bezel ticks.
"""

import argparse
import math
import os
import struct
import sys
from PIL import Image, ImageDraw, ImageFilter

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
from watchface_bin_maker import encode_image_rle_argb565, pad4_ff, push_bin_to_phone

W = 466
H = 466
CX = W // 2
CY = H // 2
PREV_SIZE = 280

COLORWAYS = {
    "green":  {"primary": (57, 255, 20),   "glow": (30, 210, 10),   "accent": (235, 255, 230), "ring": (45, 230, 20),  "rim": (38, 44, 40)},
    "albedo": {"primary": (255, 30, 45),   "glow": (200, 15, 25),   "accent": (255, 230, 235), "ring": (240, 25, 40),  "rim": (46, 36, 38)},
    "ben23":  {"primary": (0, 229, 255),   "glow": (0, 170, 220),   "accent": (255, 215, 0),   "ring": (0, 215, 255),  "rim": (34, 42, 48)},
    "gwen":   {"primary": (255, 79, 216),  "glow": (210, 40, 175),  "accent": (170, 235, 255), "ring": (245, 70, 205), "rim": (46, 36, 46)},
    "mad":    {"primary": (255, 123, 0),   "glow": (210, 85, 0),    "accent": (255, 240, 220), "ring": (255, 115, 0),  "rim": (48, 40, 34)},
    "nega":   {"primary": (200, 214, 229), "glow": (130, 150, 170), "accent": (245, 250, 255), "ring": (180, 196, 212),"rim": (38, 40, 44)},
}


def hex_to_rgb(hex_str):
    s = hex_str.strip().lstrip("#")
    if len(s) == 3:
        s = "".join(c * 2 for c in s)
    return (int(s[0:2], 16), int(s[2:4], 16), int(s[4:6], 16))


def palette_from_hex(hex_color, accent_hex=None):
    p = hex_to_rgb(hex_color)
    glow = tuple(max(0, int(c * 0.8)) for c in p)
    accent = hex_to_rgb(accent_hex) if accent_hex else tuple(min(255, int(c + (255 - c) * 0.72)) for c in p)
    ring = tuple(max(0, int(c * 0.92)) for c in p)
    rim = (36 + p[0] // 22, 38 + p[1] // 22, 40 + p[2] // 22)
    return {"primary": p, "glow": glow, "accent": accent, "ring": ring, "rim": rim}


def resolve_palette(colorway="green", custom_hex=None):
    if custom_hex:
        return palette_from_hex(custom_hex)
    return COLORWAYS.get(colorway, COLORWAYS["green"])


def _draw_ticks(draw, cx, cy, S, r1_h=191, r2_h=209, r1_m=196, r2_m=206, light_bezel=False):
    for i in range(60):
        rad = math.radians(i * 6 - 90)
        is_hour = (i % 5 == 0)
        r1 = (r1_h if is_hour else r1_m) * S
        r2 = (r2_h if is_hour else r2_m) * S
        x1, y1 = cx + math.cos(rad) * r1, cy + math.sin(rad) * r1
        x2, y2 = cx + math.cos(rad) * r2, cy + math.sin(rad) * r2
        if light_bezel:
            col = (28, 34, 32, 220) if is_hour else (80, 90, 86, 150)
        else:
            col = (210, 225, 215, 200) if is_hour else (110, 125, 115, 130)
        draw.line([(x1, y1), (x2, y2)], fill=col, width=(4 if is_hour else 2) * S)


def _apply_round_mask(img):
    img = img.resize((W, H), Image.Resampling.LANCZOS)
    mask = Image.new("L", (W, H), 0)
    ImageDraw.Draw(mask).ellipse((0, 0, W - 1, H - 1), fill=255)
    final = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    final.paste(img, (0, 0), mask)
    return final


def draw_omnitrix_bg(style="alien_force", palette=None, show_ticks=True, glow_strength=1.0):
    """Render 466x466 Omnitrix faceplate for style in ('alien_force', 'os', 'omniverse', '5yl')."""
    if palette is None:
        palette = COLORWAYS["green"]
    S = 2
    img = Image.new("RGBA", (W * S, H * S), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    cx, cy = CX * S, CY * S
    prim = palette["primary"]
    glow_col = palette["glow"]
    rim = palette["rim"]
    blur_r = max(1, int(12 * S * glow_strength))

    # Outer dark base
    r_outer = 232 * S
    draw.ellipse((cx - r_outer, cy - r_outer, cx + r_outer, cy + r_outer), fill=(8, 10, 9, 255))

    if style == "os":
        # Original Series: Metallic silver-grey outer dial, 4 glowing rim buttons at 45/135/225/315, crisp black/green hourglass
        r_bezel_out = 216 * S
        r_bezel_in = 178 * S
        draw.ellipse((cx - r_bezel_out, cy - r_bezel_out, cx + r_bezel_out, cy + r_bezel_out), fill=(175, 182, 180, 255))
        draw.ellipse((cx - r_bezel_out + 8, cy - r_bezel_out + 8, cx + r_bezel_out - 8, cy + r_bezel_out - 8),
                     outline=(110, 118, 116, 255), width=6)
        draw.ellipse((cx - r_bezel_in, cy - r_bezel_in, cx + r_bezel_in, cy + r_bezel_in), fill=(16, 18, 17, 255))

        # 4 Classic round glowing bezel buttons
        btn_layer = Image.new("RGBA", (W * S, H * S), (0, 0, 0, 0))
        bd = ImageDraw.Draw(btn_layer)
        for deg in (45, 135, 225, 315):
            rad = math.radians(deg)
            nx = cx + math.cos(rad) * (197 * S)
            ny = cy + math.sin(rad) * (197 * S)
            bd.ellipse((nx - 16 * S, ny - 16 * S, nx + 16 * S, ny + 16 * S), fill=(35, 40, 38, 255))
            bd.ellipse((nx - 11 * S, ny - 11 * S, nx + 11 * S, ny + 11 * S), fill=(*prim, 255))
        if glow_strength > 0:
            img = Image.alpha_composite(img, btn_layer.filter(ImageFilter.GaussianBlur(radius=max(1, int(6 * S * glow_strength)))))
        img = Image.alpha_composite(img, btn_layer)
        draw = ImageDraw.Draw(img)

        r_core = 166 * S
        core_layer = Image.new("RGBA", (W * S, H * S), (0, 0, 0, 0))
        ImageDraw.Draw(core_layer).ellipse((cx - r_core, cy - r_core, cx + r_core, cy + r_core), fill=(*prim, 255))
        if glow_strength > 0:
            img = Image.alpha_composite(img, core_layer.filter(ImageFilter.GaussianBlur(radius=blur_r)))
        img = Image.alpha_composite(img, core_layer)

        # Classic OS wide black side wedges with white inner rim
        plate = Image.new("RGBA", (W * S, H * S), (0, 0, 0, 0))
        pd = ImageDraw.Draw(plate)
        waist = 10 * S
        dx = math.cos(math.radians(46)) * (170 * S)
        dy = math.sin(math.radians(46)) * (170 * S)
        pd.polygon([(cx - waist, cy), (cx - dx, cy - dy), (cx - 190 * S, cy - dy), (cx - 190 * S, cy + dy), (cx - dx, cy + dy)], fill=(12, 14, 13, 255))
        pd.polygon([(cx + waist, cy), (cx + dx, cy - dy), (cx + 190 * S, cy - dy), (cx + 190 * S, cy + dy), (cx + dx, cy + dy)], fill=(12, 14, 13, 255))
        pd.line([(cx - waist, cy), (cx - dx, cy - dy)], fill=(210, 218, 215, 255), width=6 * S)
        pd.line([(cx - waist, cy), (cx - dx, cy + dy)], fill=(210, 218, 215, 255), width=6 * S)
        pd.line([(cx + waist, cy), (cx + dx, cy - dy)], fill=(210, 218, 215, 255), width=6 * S)
        pd.line([(cx + waist, cy), (cx + dx, cy + dy)], fill=(210, 218, 215, 255), width=6 * S)

        cmask = Image.new("L", (W * S, H * S), 0)
        ImageDraw.Draw(cmask).ellipse((cx - r_core, cy - r_core, cx + r_core, cy + r_core), fill=255)
        clipped = Image.new("RGBA", (W * S, H * S), (0, 0, 0, 0))
        clipped.paste(plate, (0, 0), cmask)
        img = Image.alpha_composite(img, clipped)
        draw = ImageDraw.Draw(img)
        if show_ticks:
            _draw_ticks(draw, cx, cy, S, 184, 206, 190, 202, light_bezel=True)
        return _apply_round_mask(img)

    elif style == "omniverse":
        # Omniverse: Clean white + matte black architectural bezel with sharp angular green hourglass
        r_bezel_out = 216 * S
        r_bezel_in = 182 * S
        draw.ellipse((cx - r_bezel_out, cy - r_bezel_out, cx + r_bezel_out, cy + r_bezel_out), fill=(232, 236, 238, 255))
        draw.ellipse((cx - r_bezel_out + 12, cy - r_bezel_out + 12, cx + r_bezel_out - 12, cy + r_bezel_out - 12),
                     outline=(22, 26, 28, 255), width=10 * S)
        draw.ellipse((cx - r_bezel_in, cy - r_bezel_in, cx + r_bezel_in, cy + r_bezel_in), fill=(12, 14, 15, 255))

        r_core = 172 * S
        core_layer = Image.new("RGBA", (W * S, H * S), (0, 0, 0, 0))
        cd = ImageDraw.Draw(core_layer)
        cd.ellipse((cx - r_core, cy - r_core, cx + r_core, cy + r_core), fill=(*prim, 255))
        if glow_strength > 0:
            img = Image.alpha_composite(img, core_layer.filter(ImageFilter.GaussianBlur(radius=blur_r)))
        img = Image.alpha_composite(img, core_layer)

        # Sharp white/black geometric side plates
        plate = Image.new("RGBA", (W * S, H * S), (0, 0, 0, 0))
        pd = ImageDraw.Draw(plate)
        waist = 26 * S
        dx = math.cos(math.radians(38)) * (175 * S)
        dy = math.sin(math.radians(38)) * (175 * S)
        pd.polygon([(cx - waist, cy), (cx - dx, cy - dy), (cx - 190 * S, cy - dy), (cx - 190 * S, cy + dy), (cx - dx, cy + dy)], fill=(235, 240, 242, 255))
        pd.polygon([(cx + waist, cy), (cx + dx, cy - dy), (cx + 190 * S, cy - dy), (cx + 190 * S, cy + dy), (cx + dx, cy + dy)], fill=(235, 240, 242, 255))
        # Inner dark accent triangles
        pd.polygon([(cx - waist - 18 * S, cy), (cx - dx - 18 * S, cy - dy + 16 * S), (cx - dx - 18 * S, cy + dy - 16 * S)], fill=(18, 22, 24, 255))
        pd.polygon([(cx + waist + 18 * S, cy), (cx + dx + 18 * S, cy - dy + 16 * S), (cx + dx + 18 * S, cy + dy - 16 * S)], fill=(18, 22, 24, 255))

        cmask = Image.new("L", (W * S, H * S), 0)
        ImageDraw.Draw(cmask).ellipse((cx - r_core, cy - r_core, cx + r_core, cy + r_core), fill=255)
        clipped = Image.new("RGBA", (W * S, H * S), (0, 0, 0, 0))
        clipped.paste(plate, (0, 0), cmask)
        img = Image.alpha_composite(img, clipped)
        draw = ImageDraw.Draw(img)
        draw.ellipse((cx - r_core, cy - r_core, cx + r_core, cy + r_core), outline=(*glow_col, 230), width=4 * S)
        if show_ticks:
            _draw_ticks(draw, cx, cy, S, 188, 208, 193, 204, light_bezel=True)
        return _apply_round_mask(img)

    elif style == "5yl":
        # 5 Years Later: Dark carbon bezel, double concentric glowing ring + sharp cyber hourglass
        r_bezel_out = 216 * S
        r_bezel_in = 180 * S
        draw.ellipse((cx - r_bezel_out, cy - r_bezel_out, cx + r_bezel_out, cy + r_bezel_out), fill=(22, 26, 28, 255))
        draw.ellipse((cx - 208 * S, cy - 208 * S, cx + 208 * S, cy + 208 * S), outline=(*glow_col, 160), width=3 * S)
        draw.ellipse((cx - r_bezel_in, cy - r_bezel_in, cx + r_bezel_in, cy + r_bezel_in), fill=(8, 10, 11, 255))

        # 8 glowing micro-segments around bezel
        seg_layer = Image.new("RGBA", (W * S, H * S), (0, 0, 0, 0))
        sd = ImageDraw.Draw(seg_layer)
        for deg in range(0, 360, 45):
            rad = math.radians(deg)
            x1, y1 = cx + math.cos(rad) * (186 * S), cy + math.sin(rad) * (186 * S)
            x2, y2 = cx + math.cos(rad) * (202 * S), cy + math.sin(rad) * (202 * S)
            sd.line([(x1, y1), (x2, y2)], fill=(*prim, 255), width=6 * S)
        if glow_strength > 0:
            img = Image.alpha_composite(img, seg_layer.filter(ImageFilter.GaussianBlur(radius=max(1, int(5 * S * glow_strength)))))
        img = Image.alpha_composite(img, seg_layer)

        r_core = 170 * S
        core_layer = Image.new("RGBA", (W * S, H * S), (0, 0, 0, 0))
        cd = ImageDraw.Draw(core_layer)
        cd.ellipse((cx - r_core, cy - r_core, cx + r_core, cy + r_core), fill=(*prim, 255))
        if glow_strength > 0:
            img = Image.alpha_composite(img, core_layer.filter(ImageFilter.GaussianBlur(radius=blur_r)))
        img = Image.alpha_composite(img, core_layer)

        plate = Image.new("RGBA", (W * S, H * S), (0, 0, 0, 0))
        pd = ImageDraw.Draw(plate)
        waist = 12 * S
        dx = math.cos(math.radians(35)) * (174 * S)
        dy = math.sin(math.radians(35)) * (174 * S)
        pd.polygon([(cx - waist, cy), (cx - dx, cy - dy), (cx - 190 * S, cy - dy), (cx - 190 * S, cy + dy), (cx - dx, cy + dy)], fill=(12, 14, 16, 255))
        pd.polygon([(cx + waist, cy), (cx + dx, cy - dy), (cx + 190 * S, cy - dy), (cx + 190 * S, cy + dy), (cx + dx, cy + dy)], fill=(12, 14, 16, 255))
        # Cyber neon double edge
        pd.line([(cx - waist, cy), (cx - dx, cy - dy)], fill=(*palette["accent"], 255), width=4 * S)
        pd.line([(cx - waist, cy), (cx - dx, cy + dy)], fill=(*palette["accent"], 255), width=4 * S)
        pd.line([(cx + waist, cy), (cx + dx, cy - dy)], fill=(*palette["accent"], 255), width=4 * S)
        pd.line([(cx + waist, cy), (cx + dx, cy + dy)], fill=(*palette["accent"], 255), width=4 * S)

        cmask = Image.new("L", (W * S, H * S), 0)
        ImageDraw.Draw(cmask).ellipse((cx - r_core, cy - r_core, cx + r_core, cy + r_core), fill=255)
        clipped = Image.new("RGBA", (W * S, H * S), (0, 0, 0, 0))
        clipped.paste(plate, (0, 0), cmask)
        img = Image.alpha_composite(img, clipped)
        draw = ImageDraw.Draw(img)
        if show_ticks:
            _draw_ticks(draw, cx, cy, S, light_bezel=False)
        return _apply_round_mask(img)

    # Default: Alien Force / UAF
    r_bezel_out = 216 * S
    r_bezel_in = 186 * S
    draw.ellipse((cx - r_bezel_out, cy - r_bezel_out, cx + r_bezel_out, cy + r_bezel_out), fill=(*rim, 255))
    draw.ellipse((cx - r_bezel_out + 6, cy - r_bezel_out + 6, cx + r_bezel_out - 6, cy + r_bezel_out - 6),
                 outline=(72, 82, 76, 255), width=4)
    draw.ellipse((cx - r_bezel_in, cy - r_bezel_in, cx + r_bezel_in, cy + r_bezel_in), fill=(10, 12, 11, 255))

    notch_layer = Image.new("RGBA", (W * S, H * S), (0, 0, 0, 0))
    nd = ImageDraw.Draw(notch_layer)
    for deg in (45, 135, 225, 315):
        rad = math.radians(deg)
        nx = cx + math.cos(rad) * (201 * S)
        ny = cy + math.sin(rad) * (201 * S)
        nr = 10 * S
        nd.ellipse((nx - nr, ny - nr, nx + nr, ny + nr), fill=(*prim, 255))
    if glow_strength > 0:
        img = Image.alpha_composite(img, notch_layer.filter(ImageFilter.GaussianBlur(radius=max(1, int(8 * S * glow_strength)))))
    img = Image.alpha_composite(img, notch_layer)

    r_core = 176 * S
    core_layer = Image.new("RGBA", (W * S, H * S), (0, 0, 0, 0))
    cd = ImageDraw.Draw(core_layer)
    cd.ellipse((cx - r_core, cy - r_core, cx + r_core, cy + r_core), fill=(*prim, 255))
    r_hi = 148 * S
    hi_col = tuple(min(255, c + 35) for c in prim)
    cd.ellipse((cx - r_hi, cy - r_hi, cx + r_hi, cy + r_hi), fill=(*hi_col, 255))
    if glow_strength > 0:
        img = Image.alpha_composite(img, core_layer.filter(ImageFilter.GaussianBlur(radius=blur_r)))
    img = Image.alpha_composite(img, core_layer)

    plate_layer = Image.new("RGBA", (W * S, H * S), (0, 0, 0, 0))
    pd = ImageDraw.Draw(plate_layer)
    r_p = 178 * S
    waist = 16 * S
    dx = math.cos(math.radians(42)) * r_p
    dy = math.sin(math.radians(42)) * r_p
    pd.polygon([(cx - waist, cy), (cx - dx, cy - dy), (cx - r_p - 20, cy - dy), (cx - r_p - 20, cy + dy), (cx - dx, cy + dy)], fill=(14, 16, 15, 255))
    pd.polygon([(cx + waist, cy), (cx + dx, cy - dy), (cx + r_p + 20, cy - dy), (cx + r_p + 20, cy + dy), (cx + dx, cy + dy)], fill=(14, 16, 15, 255))
    trim = (44, 52, 48, 255)
    pd.line([(cx - waist, cy), (cx - dx, cy - dy)], fill=trim, width=5 * S)
    pd.line([(cx - waist, cy), (cx - dx, cy + dy)], fill=trim, width=5 * S)
    pd.line([(cx + waist, cy), (cx + dx, cy - dy)], fill=trim, width=5 * S)
    pd.line([(cx + waist, cy), (cx + dx, cy + dy)], fill=trim, width=5 * S)

    core_mask = Image.new("L", (W * S, H * S), 0)
    ImageDraw.Draw(core_mask).ellipse((cx - r_core, cy - r_core, cx + r_core, cy + r_core), fill=255)
    plate_clipped = Image.new("RGBA", (W * S, H * S), (0, 0, 0, 0))
    plate_clipped.paste(plate_layer, (0, 0), core_mask)
    img = Image.alpha_composite(img, plate_clipped)
    draw = ImageDraw.Draw(img)
    draw.ellipse((cx - r_core, cy - r_core, cx + r_core, cy + r_core), outline=(*glow_col, 220), width=3 * S)
    if show_ticks:
        _draw_ticks(draw, cx, cy, S, light_bezel=False)
    return _apply_round_mask(img)


def draw_alien_force_bg(palette, show_ticks=True):
    return draw_omnitrix_bg("alien_force", palette=palette, show_ticks=show_ticks)


def draw_battery_ring_frames(palette):
    frames = []
    ring_col = palette["ring"]
    bbox = (5, 5, W - 6, H - 6)
    for step in range(11):
        img = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        if step > 0:
            draw = ImageDraw.Draw(img)
            draw.arc(bbox, start=-90, end=270, fill=(25, 32, 28, 180), width=6)
            sweep = int(360 * step / 10)
            col = (255, 45, 45, 255) if step <= 2 else (*ring_col, 255)
            draw.arc(bbox, start=-90, end=-90 + sweep, fill=col, width=6)
        frames.append(img)
    return frames


def draw_omnitrix_hands(palette):
    prim = palette["primary"]
    accent = palette["accent"]

    hw, hh = 32, 175
    hx, hy = CX - hw // 2, CY - hh
    h_img = Image.new("RGBA", (hw, hh), (0, 0, 0, 0))
    hd = ImageDraw.Draw(h_img)
    hd.ellipse((hw // 2 - 12, 6, hw // 2 + 12, 30), fill=(10, 12, 11, 255))
    hd.ellipse((hw // 2 - 9, 9, hw // 2 + 9, 27), fill=(*accent, 255))
    hd.ellipse((hw // 2 - 5, 13, hw // 2 + 5, 23), fill=(*prim, 255))

    mw, mh = 22, 205
    mx, my = CX - mw // 2, CY - mh
    m_img = Image.new("RGBA", (mw, mh), (0, 0, 0, 0))
    md = ImageDraw.Draw(m_img)
    md.rounded_rectangle((mw // 2 - 7, 4, mw // 2 + 7, 44), radius=3, fill=(10, 12, 11, 255))
    md.rounded_rectangle((mw // 2 - 4, 7, mw // 2 + 4, 41), radius=2, fill=(*accent, 255))

    sw, sh = 18, 221
    sx, sy = CX - sw // 2, CY - sh
    s_img = Image.new("RGBA", (sw, sh), (0, 0, 0, 0))
    sd = ImageDraw.Draw(s_img)
    sd.rounded_rectangle((sw // 2 - 6, 2, sw // 2 + 6, 18), radius=2, fill=(10, 12, 11, 255))
    sd.rounded_rectangle((sw // 2 - 4, 4, sw // 2 + 4, 16), radius=2, fill=(*prim, 255))

    return [(0, hx, hy, h_img), (1, mx, my, m_img), (2, sx, sy, s_img)]


def render_preview(bg_img, batt_frame, hands):
    comp = bg_img.copy()
    if batt_frame is not None:
        comp = Image.alpha_composite(comp, batt_frame)
    angles = {0: -305, 1: -60, 2: -210}
    for hid, hx, hy, himg in hands:
        full = Image.new("RGBA", (W, H), (0, 0, 0, 0))
        full.paste(himg, (hx, hy))
        rot = full.rotate(angles[hid], resample=Image.Resampling.BICUBIC, center=(CX, CY))
        comp = Image.alpha_composite(comp, rot)
    return comp


def build_omnitrix_bin(out_bin_path, style="alien_force", colorway="green", custom_hex=None, show_ticks=True, glow_strength=1.0, save_preview_path=None):
    palette = resolve_palette(colorway, custom_hex)
    bg_img = draw_omnitrix_bg(style=style, palette=palette, show_ticks=show_ticks, glow_strength=glow_strength)
    batt_frames = draw_battery_ring_frames(palette)
    hands = draw_omnitrix_hands(palette)

    full_preview = render_preview(bg_img, batt_frames[8], hands)
    if save_preview_path:
        os.makedirs(os.path.dirname(os.path.abspath(save_preview_path)), exist_ok=True)
        full_preview.save(save_preview_path)

    prev_img = full_preview.resize((PREV_SIZE, PREV_SIZE), Image.Resampling.LANCZOS)
    bg_blob = encode_image_rle_argb565(bg_img)
    batt_blobs = [encode_image_rle_argb565(f) for f in batt_frames]
    hand_blobs = [encode_image_rle_argb565(h[3]) for h in hands]
    prev_blob = encode_image_rle_argb565(prev_img)

    header_len = 16 + 14 + (8 + 11 * 8) + (3 * 19) + 2
    img_start = (header_len + 3) & ~3
    out = bytearray(img_start)

    bg_off = len(out); out.extend(bg_blob); pad4_ff(out)
    batt_offs = []
    for b in batt_blobs:
        batt_offs.append(len(out)); out.extend(b); pad4_ff(out)
    hand_offs = []
    for h in hand_blobs:
        hand_offs.append(len(out)); out.extend(h); pad4_ff(out)
    prev_off = len(out); out.extend(prev_blob); pad4_ff(out)

    struct.pack_into('<HHIHHHH', out, 0x00, 0x0012, 0xFFFF, prev_off, PREV_SIZE, PREV_SIZE, 0x0000, 0x0010)
    p = 0x10
    struct.pack_into('<BBHHIHH', out, p, 0x01, 0x00, 0, 0, bg_off, W, H); p += 14
    struct.pack_into('<BBBBHH', out, p, 0x01, 0x12, 0x06, 11, 0, 0); p += 8
    for boff in batt_offs:
        struct.pack_into('<IHH', out, p, boff, W, H); p += 8
    for idx, (hid, hx, hy, himg) in enumerate(hands):
        struct.pack_into('<BBBHHIHHI', out, p, 0x01, 0x0a, hid, hx, hy, hand_offs[idx], himg.width, himg.height, 0xFFFFFFFF)
        p += 19
    out[p:p+2] = b'\x00\x00'

    os.makedirs(os.path.dirname(os.path.abspath(out_bin_path)), exist_ok=True)
    with open(out_bin_path, 'wb') as f:
        f.write(out)
    return out_bin_path


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Haylou Watch 4S - Ben 10 Omnitrix Watchface Maker")
    parser.add_argument("--style", choices=["alien_force", "os", "omniverse", "5yl"], default="alien_force")
    parser.add_argument("--color", choices=list(COLORWAYS.keys()), default="green")
    parser.add_argument("--hex", default=None, help="Custom hex color e.g. #39FF14")
    parser.add_argument("--no-ticks", action="store_true")
    parser.add_argument("-o", "--out", default=None)
    parser.add_argument("--push", action="store_true")
    args = parser.parse_args()
    out_path = args.out or os.path.join(SCRIPT_DIR, "..", "samples", f"omnitrix_{args.style}_{args.color}.bin")
    build_omnitrix_bin(out_path, style=args.style, colorway=args.color, custom_hex=args.hex, show_ticks=not args.no_ticks)
    if args.push:
        push_bin_to_phone(out_path)
