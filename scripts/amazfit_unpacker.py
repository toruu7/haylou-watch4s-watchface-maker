"""
Amazfit Watchface (.bin) Unpacker for Haylou Watch 4S Studio.

Supports Huami/Amazfit `UIHH` containers (QuickLZ 1.5.0 Level 3 compressed or
uncompressed) as well as raw `BM\\xff\\xff` 32-bit BGRA and standard Windows BMP
bitmaps. Extracts the primary circular background (upscaled & sharpened to
466x466 round AMOLED) plus a gallery of smaller assets.
"""

from __future__ import annotations

import io
import os
import struct
from PIL import Image, ImageDraw, ImageFilter

WATCH_SIZE = 466


def qlz_decompress_block(src: bytes, start: int = 0) -> tuple[bytes, int]:
    """Decompress a single QuickLZ 1.5.0 Level 3 block starting at `start`."""
    flags = src[start]
    if flags & 2:
        csize, usize = struct.unpack_from("<II", src, start + 1)
        pos = start + 9
    else:
        csize, usize = src[start + 1], src[start + 2]
        pos = start + 3
    if csize <= 0 or start + csize > len(src):
        raise ValueError(f"Invalid QuickLZ block size {csize} at 0x{start:x}")
    if (flags & 1) == 0:
        return bytes(src[pos : pos + usize]), start + csize

    dst = bytearray()
    cword_val = 1
    end_pos = start + csize
    while len(dst) < usize and pos < end_pos:
        if cword_val == 1:
            if pos + 4 > end_pos:
                break
            cword_val = struct.unpack_from("<I", src, pos)[0]
            pos += 4
        if cword_val & 1:
            fetch = src[pos]
            if (fetch & 3) == 0:
                offset = fetch >> 2
                matchlen = 3
                pos += 1
            elif (fetch & 2) == 0:
                fetch16 = struct.unpack_from("<H", src, pos)[0]
                offset = fetch16 >> 2
                matchlen = 3
                pos += 2
            elif (fetch & 1) == 0:
                fetch16 = struct.unpack_from("<H", src, pos)[0]
                offset = fetch16 >> 6
                matchlen = ((fetch16 >> 2) & 15) + 3
                pos += 2
            elif (fetch & 127) != 3:
                fetch32 = struct.unpack_from("<I", src, pos)[0]
                offset = (fetch32 >> 7) & 0x1FFFF
                matchlen = ((fetch32 >> 2) & 0x1F) + 2
                pos += 3
            else:
                fetch32 = struct.unpack_from("<I", src, pos)[0]
                offset = fetch32 >> 15
                matchlen = ((fetch32 >> 7) & 255) + 3
                pos += 4
            if offset <= 0 or offset > len(dst):
                raise ValueError(f"Invalid QuickLZ backreference offset={offset} at dst={len(dst)}")
            for _ in range(matchlen):
                dst.append(dst[-offset])
        else:
            dst.append(src[pos])
            pos += 1
        cword_val >>= 1
    return bytes(dst), start + csize


def decompress_uihh_payload(raw: bytes) -> bytes:
    """If `raw` is a QuickLZ-compressed Amazfit `UIHH` container, decompress it; else return `raw`."""
    if len(raw) < 0x30 or not raw.startswith(b"UIHH"):
        return raw
    # Check if offset 0x28 starts a QuickLZ L3 block (flags typically 0x4f / 0x4d / 0x0f)
    total_usize = struct.unpack_from("<I", raw, 0x20)[0]
    first_flag = raw[0x28]
    if 0x1000 <= total_usize <= 32 * 1024 * 1024 and (first_flag & 0x0C) == 0x0C:
        out = bytearray()
        off = 0x28
        while off < len(raw) and len(out) < total_usize:
            if raw[off] == 0:
                break
            try:
                chunk, next_off = qlz_decompress_block(raw, off)
            except Exception:
                break
            out.extend(chunk)
            if next_off <= off:
                break
            off = next_off
        if len(out) >= 4096:
            return bytes(out)
    return raw


def extract_huami_bitmaps(payload: bytes) -> list[dict]:
    """Scan decompressed Amazfit payload for Huami `BM\\xff\\xff` and standard BMP images."""
    results: list[dict] = []
    seen_offsets: set[int] = set()

    # 1. Huami BM\xff\xff 32-bit BGRA / 24-bit BGR bitmaps
    pos = 0
    while True:
        idx = payload.find(b"BM\xff\xff", pos)
        if idx == -1:
            break
        if idx + 24 <= len(payload):
            w, h, bpp, _u1, _u2 = struct.unpack_from("<IIIII", payload, idx + 4)
            if 2 <= w <= 600 and 2 <= h <= 600 and bpp in (24, 32):
                step = bpp // 8
                need = w * h * step
                raw_px = payload[idx + 24 : idx + 24 + need]
                if len(raw_px) == need:
                    try:
                        if bpp == 32:
                            im = Image.frombytes("RGBA", (w, h), raw_px, "raw", "BGRA")
                        else:
                            im = Image.frombytes("RGB", (w, h), raw_px, "raw", "BGR").convert("RGBA")
                        results.append({"offset": idx, "width": w, "height": h, "bpp": bpp, "image": im})
                        seen_offsets.add(idx)
                        pos = idx + 24 + need
                        continue
                    except Exception:
                        pass
        pos = idx + 4

    # 2. Fallback: standard Windows BMPs (e.g. T-Rex / older Amazfit)
    if not results:
        pos = 0
        while True:
            idx = payload.find(b"BM", pos)
            if idx == -1:
                break
            if idx not in seen_offsets and idx + 26 <= len(payload):
                fsize = struct.unpack_from("<I", payload, idx + 2)[0]
                dib = struct.unpack_from("<I", payload, idx + 14)[0]
                if 54 <= fsize <= 2_000_000 and dib in (40, 52, 56, 108, 124) and idx + fsize <= len(payload):
                    try:
                        im = Image.open(io.BytesIO(payload[idx : idx + fsize])).convert("RGBA")
                        results.append({"offset": idx, "width": im.width, "height": im.height, "bpp": 32, "image": im})
                        pos = idx + fsize
                        continue
                    except Exception:
                        pass
            pos = idx + 2

    return results


def prepare_watch4s_background(im: Image.Image) -> Image.Image:
    """Upscale/center-fit an extracted Amazfit background to 466x466 circular AMOLED."""
    src = im.convert("RGBA")
    if src.size != (WATCH_SIZE, WATCH_SIZE):
        src = src.resize((WATCH_SIZE, WATCH_SIZE), Image.LANCZOS)
        src = src.filter(ImageFilter.UnsharpMask(radius=1.0, percent=110, threshold=2))
    base = Image.new("RGBA", (WATCH_SIZE, WATCH_SIZE), (0, 0, 0, 255))
    base.alpha_composite(src)
    mask = Image.new("L", (WATCH_SIZE, WATCH_SIZE), 0)
    ImageDraw.Draw(mask).ellipse((0, 0, WATCH_SIZE - 1, WATCH_SIZE - 1), fill=255)
    out = Image.new("RGBA", (WATCH_SIZE, WATCH_SIZE), (0, 0, 0, 0))
    out.paste(base, (0, 0), mask)
    return out


def unpack_amazfit_bin(raw: bytes) -> dict:
    """
    Unpack an Amazfit `.bin` watchface and return:
      - `background`: 466x466 Watch 4S-ready RGBA Image (largest square/dial image)
      - `preview`: optional reference preview Image (second largest square image if present)
      - `source_size`: (w, h) of the original background
      - `total_images`: total extracted bitmaps count
      - `decompressed_bytes`: size of decompressed payload
    """
    if not raw or len(raw) < 64:
        raise ValueError("File is too small to be an Amazfit watchface .bin.")
    payload = decompress_uihh_payload(raw)
    bitmaps = extract_huami_bitmaps(payload)
    if not bitmaps:
        raise ValueError("No supported Amazfit bitmaps found in this .bin (expected UIHH/QuickLZ or BMP).")

    # Pick largest image (prefer square dial background)
    ranked = sorted(
        bitmaps,
        key=lambda b: (1 if abs(b["width"] - b["height"]) <= 4 else 0, b["width"] * b["height"]),
        reverse=True,
    )
    bg_item = ranked[0]
    bg466 = prepare_watch4s_background(bg_item["image"])

    # Optional preview thumbnail (often 220x220 or second-largest square image)
    preview_im = None
    for cand in ranked[1:]:
        if abs(cand["width"] - cand["height"]) <= 4 and cand["width"] >= 140:
            preview_im = cand["image"]
            break

    return {
        "background": bg466,
        "preview": preview_im,
        "source_size": (bg_item["width"], bg_item["height"]),
        "total_images": len(bitmaps),
        "decompressed_bytes": len(payload),
    }
