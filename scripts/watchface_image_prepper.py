"""
Haylou Watch 4S (LS26) Watchface Image Prepper
Automates resizing, cropping, and previewing custom watchface backgrounds for 466x466 round AMOLED displays.

Features:
- Scales & center-crops any input image to exact 466x466 pixels.
- Generates 150x150 thumbnail for the companion app dial manager.
- Generates a simulated circular AMOLED watch bezel preview to check border cutoff.
- Optional --adb flag to instantly push the prepped image to your connected phone's Gallery.
"""

import os
import sys
import argparse
import subprocess
from PIL import Image, ImageDraw, ImageOps

WATCH_WIDTH = 466
WATCH_HEIGHT = 466
THUMB_WIDTH = 150
THUMB_HEIGHT = 150

def push_to_phone(file_path):
    print(f"[*] Pushing {os.path.basename(file_path)} to connected Android phone via ADB...")
    dest = f"/sdcard/Pictures/{os.path.basename(file_path)}"
    res = subprocess.run(["adb", "push", file_path, dest], capture_output=True, text=True)
    if res.returncode == 0:
        # Trigger MediaScanner so Gallery indexes it immediately
        subprocess.run(["adb", "shell", "am", "broadcast", "-a", "android.intent.action.MEDIA_SCANNER_SCAN_FILE", "-d", f"file://{dest}"], capture_output=True)
        print(f"[+] Successfully pushed to phone: {dest} (visible in Gallery!)")
        return True
    else:
        print(f"[-] ADB push failed: {res.stderr.strip()}")
        return False

def prep_image(input_path, output_dir=None, push_adb=False):
    if not os.path.exists(input_path):
        print(f"[-] Input file not found: {input_path}")
        return False

    if output_dir is None:
        output_dir = os.path.dirname(input_path) or "."
    os.makedirs(output_dir, exist_ok=True)

    base_name = os.path.splitext(os.path.basename(input_path))[0]
    
    print(f"[*] Processing image: {input_path}")
    img = Image.open(input_path).convert("RGBA")
    
    # 1. Center crop and scale to 466x466
    target_ratio = WATCH_WIDTH / WATCH_HEIGHT
    img_ratio = img.width / img.height
    
    if img_ratio > target_ratio:
        new_width = int(img.height * target_ratio)
        offset = (img.width - new_width) // 2
        img_cropped = img.crop((offset, 0, offset + new_width, img.height))
    else:
        new_height = int(img.width / target_ratio)
        offset = (img.height - new_height) // 2
        img_cropped = img.crop((0, offset, img.width, offset + new_height))
        
    img_466 = img_cropped.resize((WATCH_WIDTH, WATCH_HEIGHT), Image.Resampling.LANCZOS)
    
    # Save 466x466 RGB version (for upload)
    rgb_466 = img_466.convert("RGB")
    out_466_path = os.path.join(output_dir, f"{base_name}_466x466.png")
    rgb_466.save(out_466_path, quality=95)
    print(f"[+] Saved 466x466 AMOLED image: {out_466_path}")
    
    # 2. Thumbnail (150x150)
    thumb = rgb_466.resize((THUMB_WIDTH, THUMB_HEIGHT), Image.Resampling.LANCZOS)
    out_thumb_path = os.path.join(output_dir, f"{base_name}_thumb.png")
    thumb.save(out_thumb_path)
    print(f"[+] Saved 150x150 thumbnail: {out_thumb_path}")
    
    # 3. AMOLED Circular bezel simulated preview
    bezel_size = 560
    bezel_canvas = Image.new("RGBA", (bezel_size, bezel_size), (24, 24, 26, 255))
    draw = ImageDraw.Draw(bezel_canvas)
    
    # Outer watch case bezel
    draw.ellipse((20, 20, bezel_size - 20, bezel_size - 20), outline=(50, 50, 55), width=8)
    draw.ellipse((35, 35, bezel_size - 35, bezel_size - 35), outline=(15, 15, 18), width=12)
    
    # Circular mask for display
    mask = Image.new("L", (WATCH_WIDTH, WATCH_HEIGHT), 0)
    mask_draw = ImageDraw.Draw(mask)
    mask_draw.ellipse((0, 0, WATCH_WIDTH, WATCH_HEIGHT), fill=255)
    
    paste_pos = ((bezel_size - WATCH_WIDTH) // 2, (bezel_size - WATCH_HEIGHT) // 2)
    bezel_canvas.paste(rgb_466, paste_pos, mask)
    
    out_preview_path = os.path.join(output_dir, f"{base_name}_round_preview.png")
    bezel_canvas.save(out_preview_path)
    print(f"[+] Saved circular watch bezel preview: {out_preview_path}")

    # 4. Optional push to phone
    if push_adb:
        push_to_phone(out_466_path)
    
    return {
        "watchface": out_466_path,
        "thumbnail": out_thumb_path,
        "preview": out_preview_path
    }

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Haylou Watch 4S Image Prepper")
    parser.add_argument("image", help="Input image file (PNG/JPG/WEBP)")
    parser.add_argument("-o", "--outdir", default=None, help="Output directory")
    parser.add_argument("--push", action="store_true", help="Push 466x466 image to connected phone via ADB")
    args = parser.parse_args()
    
    prep_image(args.image, args.outdir, push_adb=args.push)
