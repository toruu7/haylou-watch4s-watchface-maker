"""
Haylou Watch 4S (LS26) True .bin Watchface Maker
Builds genuine JieLi / MoYoung ARGB565-RLE .bin watchface files for Haylou Watch 4S (466x466 AMOLED).

Supports:
  Phase 1 (--no-clock):
    100% pure custom 466x466 background image with ZERO clock, ZERO date, and ZERO widgets.
  Phase 2 (Custom Clock Position & Custom Fonts):
    Move the HH:MM clock to any (x, y) coordinates and render any TrueType (.ttf/.otf) font & color.
  One-Click Sideload (--push):
    Pushes the compiled .bin straight to the modded Haylou Fun app cache via ADB.
"""

import argparse
import os
import struct
import subprocess
import sys
from PIL import Image, ImageDraw, ImageFont

WATCH_W = 466
WATCH_H = 466
PREV_W = 280
PREV_H = 280
DIGIT_W = 46
DIGIT_H = 71

# Default clock digit coordinates from official Watch 4S plate (HH MM)
DEFAULT_COORDS = [
    (105, 344),  # Hour tens
    (167, 344),  # Hour ones
    (253, 344),  # Minute tens
    (315, 344),  # Minute ones
]

def rgba_to_argb565_bytes(r, g, b, a):
    if a == 0:
        return b'\x00\x00\x00'
    rgb565 = ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3)
    return bytes([a, (rgb565 >> 8) & 0xFF, rgb565 & 0xFF])

def encode_row_rle(row_pixels):
    """Encode a list of 3-byte [A, hi, lo] pixels using MoYoung/JieLi per-row RLE."""
    out = bytearray()
    n = len(row_pixels)
    i = 0
    while i < n:
        # Count repeat run
        run_len = 1
        while i + run_len < n and run_len < 127 and row_pixels[i + run_len] == row_pixels[i]:
            run_len += 1
        if run_len >= 2:
            out.append(0x80 | run_len)
            out.extend(row_pixels[i])
            i += run_len
        else:
            # Collect literal run until we hit a repeat of >= 2 or max 127
            lit_start = i
            lit_len = 0
            while i < n and lit_len < 127:
                if i + 1 < n and row_pixels[i] == row_pixels[i + 1]:
                    break
                i += 1
                lit_len += 1
            if lit_len == 0:
                lit_len = 1
                i += 1
            out.append(lit_len)
            for k in range(lit_start, lit_start + lit_len):
                out.extend(row_pixels[k])
    return bytes(out)

def encode_image_rle_argb565(img_rgba):
    """Encode a PIL RGBA Image into [height * uint32 row_table] + [RLE rows]."""
    w, h = img_rgba.size
    px = img_rgba.load()
    row_blobs = []
    for y in range(h):
        row = [rgba_to_argb565_bytes(*px[x, y]) for x in range(w)]
        row_blobs.append(encode_row_rle(row))

    table_size = h * 4
    table = bytearray()
    body = bytearray()
    cur_off = table_size
    for blob in row_blobs:
        assert cur_off <= 0x1FFFFF, f"Image too large for 21-bit row offset: {cur_off}"
        assert len(blob) <= 0x7FF, f"Row compressed length too large: {len(blob)}"
        entry = (len(blob) << 21) | (cur_off & 0x1FFFFF)
        table.extend(struct.pack('<I', entry))
        body.extend(blob)
        cur_off += len(blob)
    return bytes(table) + bytes(body)

def prepare_circular_image(img_path, size):
    img = Image.open(img_path).convert("RGBA")
    # Center crop to square
    side = min(img.width, img.height)
    left = (img.width - side) // 2
    top = (img.height - side) // 2
    img = img.crop((left, top, left + side, top + side))
    img = img.resize((size, size), Image.Resampling.LANCZOS)

    # Apply smooth circular mask (matches official Watch 4S round AMOLED dial)
    mask = Image.new("L", (size, size), 0)
    draw = ImageDraw.Draw(mask)
    draw.ellipse((0, 0, size - 1, size - 1), fill=255)
    out = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    out.paste(img, (0, 0), mask)
    return out

def render_digit_images(no_clock=True, font_path=None, font_size=60, font_color="#FFFFFF"):
    digits = []
    if no_clock:
        # 100% transparent 46x71 digits -> zero clock pixels rendered on watch
        blank = Image.new("RGBA", (DIGIT_W, DIGIT_H), (0, 0, 0, 0))
        return [blank for _ in range(10)]

    if font_path and os.path.exists(font_path):
        font = ImageFont.truetype(font_path, font_size)
    else:
        # Fallback to Windows Arial Bold or default PIL font
        win_arial = r"C:\Windows\Fonts\arialbd.ttf"
        if os.path.exists(win_arial):
            font = ImageFont.truetype(win_arial, font_size)
        else:
            font = ImageFont.load_default()

    for d in range(10):
        canvas = Image.new("RGBA", (DIGIT_W, DIGIT_H), (0, 0, 0, 0))
        draw = ImageDraw.Draw(canvas)
        text = str(d)
        bbox = draw.textbbox((0, 0), text, font=font)
        tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
        tx = (DIGIT_W - tw) // 2 - bbox[0]
        ty = (DIGIT_H - th) // 2 - bbox[1]
        draw.text((tx, ty), text, font=font, fill=font_color)
        digits.append(canvas)
    return digits

def pad4_ff(buf):
    rem = len(buf) % 4
    if rem != 0:
        buf.extend(b'\xff' * (4 - rem))

def build_watchface_bin(bg_path, out_bin_path, no_clock=True, clock_pos=None, font_path=None, font_size=60, font_color="#FFFFFF", brightness_pct=100):
    print(f"[*] Building Haylou Watch 4S .bin from: {bg_path} (AMOLED brightness={brightness_pct}%)")
    bg_img = prepare_circular_image(bg_path, WATCH_W)
    prev_img = prepare_circular_image(bg_path, PREV_W)
    if brightness_pct < 100:
        b_scale = max(0.10, min(1.0, float(brightness_pct) / 100.0))
        lut = [int(i * b_scale) for i in range(256)]
        for im in (bg_img, prev_img):
            r, g, b, a = im.split()
            im.paste(Image.merge("RGBA", (r.point(lut), g.point(lut), b.point(lut), a)))
    digit_imgs = render_digit_images(no_clock=no_clock, font_path=font_path, font_size=font_size, font_color=font_color)

    if clock_pos:
        cx, cy = clock_pos
        # Center a 4-digit HH MM block around (cx, cy) with official spacing
        coords = [
            (max(0, cx - 128), max(0, cy - DIGIT_H // 2)),
            (max(0, cx - 66),  max(0, cy - DIGIT_H // 2)),
            (max(0, cx + 20),  max(0, cy - DIGIT_H // 2)),
            (max(0, cx + 82),  max(0, cy - DIGIT_H // 2)),
        ]
    else:
        coords = DEFAULT_COORDS

    print("[*] Encoding 466x466 background (ARGB565 RLE)...")
    bg_blob = encode_image_rle_argb565(bg_img)
    print(f"    Background compressed size: {len(bg_blob)} bytes")

    print("[*] Encoding 10 clock digit bitmaps...")
    digit_blobs = [encode_image_rle_argb565(d) for d in digit_imgs]

    print("[*] Encoding 280x280 preview (ARGB565 RLE)...")
    prev_blob = encode_image_rle_argb565(prev_img)
    print(f"    Preview compressed size: {len(prev_blob)} bytes")

    # Header is fixed 0x98 (152) bytes matching official Watch 4S structure:
    #   0x00..0x0F: Main header (num_elems=2, unk=0xffff, prev_off, prev_w=280, prev_h=280, elem0_off=0x10, elem1_off=0x65)
    #   0x10..0x64: Element 0 (digit table: 01 01 00 + 10 * <IHH, + 2 zero bytes at 0x63..0x64)
    #   0x65..0x97: Element 1 (background descriptor + 4 digit (x,y) coords)
    out = bytearray(0x98)

    # Append BG at 0x98
    bg_off = len(out)
    assert bg_off == 0x98
    out.extend(bg_blob)
    pad4_ff(out)

    # Append 10 digits
    digit_offs = []
    for dblob in digit_blobs:
        digit_offs.append(len(out))
        out.extend(dblob)
        pad4_ff(out)

    # Append Preview
    prev_off = len(out)
    out.extend(prev_blob)
    pad4_ff(out)

    # Fill main header (0x00..0x0F)
    struct.pack_into('<HHIHHHH', out, 0x00, 2, 0xFFFF, prev_off, PREV_W, PREV_H, 0x0010, 0x0065)

    # Fill Element 0 (0x10..0x64): 10 clock digits
    out[0x10:0x13] = bytes([0x01, 0x01, 0x00])
    for i in range(10):
        struct.pack_into('<IHH', out, 0x13 + i * 8, digit_offs[i], DIGIT_W, DIGIT_H)

    # Fill Element 1 (0x65..0x97): background + 4 clock digit (x, y) coords
    out[0x65:0x6B] = bytes([0x01, 0x00, 0x00, 0x00, 0x00, 0x00])
    struct.pack_into('<IHH', out, 0x6B, bg_off, WATCH_W, WATCH_H)
    out[0x73:0x79] = bytes([0x01, 0x02, 0x00, 0x00, 0x00, 0x00])
    for idx, (cx, cy) in enumerate(coords):
        struct.pack_into('<HH', out, 0x79 + idx * 4, cx, cy)

    os.makedirs(os.path.dirname(os.path.abspath(out_bin_path)), exist_ok=True)
    with open(out_bin_path, 'wb') as f:
        f.write(out)

    mode_str = "NO-CLOCK (Pure Image Only)" if no_clock else f"CUSTOM CLOCK @ {coords[0]}"
    print(f"[+] Watchface .bin built successfully! [{mode_str}]")
    print(f"    Output: {out_bin_path} ({len(out):,} bytes / {len(out)/1024:.1f} KB)")
    return out_bin_path

def push_bin_to_phone(bin_path):
    dest = "/sdcard/Android/data/com.yingsheng.hayloufun/cache/ls25plate.bin"
    print(f"[*] Pushing {os.path.basename(bin_path)} -> {dest} via ADB...")
    res = subprocess.run(["adb", "push", bin_path, dest], capture_output=True, text=True)
    if res.returncode == 0:
        print(f"[+] Pushed successfully! Now tap Install/Sync on ANY free cloud dial in Haylou Fun!")
        return True
    else:
        print(f"[-] ADB push failed: {res.stderr.strip()}")
        return False

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Haylou Watch 4S (LS26) True .bin Watchface Maker")
    parser.add_argument("image", help="Path to background image (PNG/JPG/WEBP)")
    parser.add_argument("-o", "--out", default=None, help="Output .bin path")
    parser.add_argument("--with-clock", action="store_true", help="Enable digital clock (default is NO-CLOCK pure image)")
    parser.add_argument("--clock-pos", nargs=2, type=int, metavar=("X", "Y"), help="Center (X, Y) of clock on 466x466 screen")
    parser.add_argument("--font", default=None, help="Path to custom .ttf/.otf font file")
    parser.add_argument("--font-size", type=int, default=60, help="Font size in pixels (default 60)")
    parser.add_argument("--font-color", default="#FFFFFF", help="Hex color for clock digits (default #FFFFFF)")
    parser.add_argument("--brightness", type=int, default=100, help="AMOLED brightness percentage 15..100 (default 100; try 45 for low-glare)")
    parser.add_argument("--push", action="store_true", help="Push generated .bin directly to phone via ADB")
    args = parser.parse_args()

    out_path = args.out or (os.path.splitext(args.image)[0] + "_watch4s.bin")
    build_watchface_bin(
        args.image,
        out_path,
        no_clock=not args.with_clock,
        clock_pos=args.clock_pos,
        font_path=args.font,
        font_size=args.font_size,
        font_color=args.font_color,
        brightness_pct=args.brightness,
    )
    if args.push:
        push_bin_to_phone(out_path)
