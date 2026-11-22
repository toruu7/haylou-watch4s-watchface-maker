# Haylou Watch 4S Watchface Studio & `.bin` Maker

An open-source visual watchface designer, native binary (`.bin`) compiler, and ADB sideloader for the **Haylou Watch 4S** (`LS26` / `02_A6` · JieLi `JL7012A7` · `466×466` Round AMOLED).

Overcomes the default Haylou Fun companion app limitations—fixed clock placements, fixed fonts, and inability to hide the clock—by compiling **genuine JieLi / MoYoung ARGB565-RLE `.bin` watchfaces** and installing them through the watch's official cloud dial slot.

---

## Features

- **Visual Multi-Layer Watchface Studio (`launch_studio.bat`):**
  - Local dark-mode browser UI with a machined Watch 4S hardware preview (`466×466` pixel-exact rendering).
  - **Direct 1:1 drag-and-drop positioning** on the watch face with magnetic center-snap guides and live coordinate HUD.
  - **Saved Presets Library:** Save, edit, duplicate, delete, import `.bin` files, and push any preset to your phone over ADB in one click.
- **Pure Image Mode (No Clock):**
  - Full-resolution `466×466` custom artwork with **zero clock digits, zero date, and zero widgets**.
- **Pro Digital Clock & Typography:**
  - Horizontal (`HH MM`) or **Stacked Vertical** (`HH` over `MM`) layouts.
  - Upload any custom `.ttf` or `.otf` font directly in the Studio UI.
  - Vertical color gradients, stroke/outline, neon outer glow, and custom spacing.
- **60Hz Rotating Analog Hands:**
  - 4 built-in hand packs (**Omnitrix**, **Classic Needles**, **Neon Pointers**, **Minimalist Baton**) with custom colors, optional second hand, and optional center cap.
- **Native Widgets:**
  - **11-Step Battery Indicator:** Outer 360° circular ring, bottom curved arc gauge, horizontal bar, or classic pill icon (auto-switches to red at ≤20%).
  - **7-Frame Weekday Label (`SUN`–`SAT`):** Custom font, color, uppercase toggle, and draggable position.
- **Ben 10 Omnitrix Generator:**
  - 4 built-in series faceplates (**Alien Force / UAF**, **Original Series**, **Omniverse**, **5 Years Later**) with 6 preset colorways + full custom hex color picker and glow control.
- **Safe & 100% Reversible:**
  - Installs strictly into the watch's official cloud dial slot (`CRPWatchFaceInfo.WacthFaceType.JIELI`). Never flashes firmware or bootloaders. Switching watchfaces on the watch restores stock dials immediately.

---

## Requirements

- **Python 3.9+** and **Pillow** (`pip install -r requirements.txt`)
- **Android Debug Bridge (`adb`)** in your `PATH` + Android phone with **USB Debugging** enabled
- **Android SDK Build-Tools** (`zipalign` and `apksigner`) + Java `keytool` *(only needed once to patch your own copy of Haylou Fun)*
- Your own copy of the official **Haylou Fun v4.0.8 APK** *(not redistributed in this repository)*

---

## Getting Started

### 1. Clone & Install Python Dependency
```bash
git clone https://github.com/toruu7/haylou-watch4s-watchface-maker.git
cd haylou-watch4s-watchface-maker
pip install -r requirements.txt
```

### 2. Patch & Install Haylou Fun (One-Time Setup)
Obtain the official `haylou-fun-v4-0-8.apk`, then run the automated patcher. It adds a local `.bin` sideload hook (`classes6.dex`), fixes Facebook SDK key-hash validation for debug-signed builds (`classes3.dex`), aligns `resources.arsc` on a 4-byte boundary, and signs with APK Signature Scheme v2/v3 (auto-generating a local `keystore/debug.keystore` if needed):

```bash
python scripts/patch_and_build_apk.py --src /path/to/haylou-fun-v4-0-8.apk
```

Connect your Android phone via USB and install the generated APK:
```bash
adb install -r haylou-fun-v4-0-8-noclock.apk
```
> **Important:** Open Google Play Store &rarr; **Haylou Fun** &rarr; **⋮** &rarr; **uncheck "Enable auto update"** so Play Store does not overwrite your patched build.

### 3. Launch Haylou Watch 4S Studio
- **Windows:** Double-click `launch_studio.bat`
- **macOS / Linux / CLI:**
  ```bash
  python studio/server.py
  ```
Your browser will open at **http://127.0.0.1:8466**.

### 4. Apply Any Watchface to Your Watch 4S
1. In **Haylou Watch 4S Studio**, click **Save & Push** (or **Push to Watch** on any saved preset).
2. On your phone, open **Haylou Fun** (ensure Watch 4S is connected via Bluetooth).
3. Go to **Device &rarr; Dial Center / Watch Face Market**.
4. Tap **any free cloud watchface** and hit **Sync / Install**.
5. The patched app streams your custom `/sdcard/Android/data/com.yingsheng.hayloufun/cache/ls25plate.bin` directly to your Watch 4S.

---

## Command-Line Tools (Optional)

You can also compile & push watchfaces without opening the Studio UI:

```bash
# Pure 466x466 image (no clock, no date, no widgets) + ADB push:
python scripts/watchface_bin_maker.py "path/to/artwork.png" --push

# Custom clock position + custom font + color + ADB push:
python scripts/watchface_bin_maker.py "path/to/artwork.png" \
  --with-clock --clock-pos 233 120 \
  --font "C:\Windows\Fonts\impact.ttf" --font-size 64 --font-color "#00FFCC" \
  --push

# Ben 10 Omnitrix (alien_force | os | omniverse | 5yl) + custom color + ADB push:
python scripts/omnitrix_watchface_maker.py --style alien_force --color green --push
python scripts/omnitrix_watchface_maker.py --style omniverse --hex "#00E5FF" --push
```

On Windows, you can also **drag & drop any image** directly onto `make_and_push_noclock.bat`.

---

## Reverse-Engineered Watch 4S `.bin` Format

Full technical notes live in [`docs/protocol_specs.md`](docs/protocol_specs.md) and [`docs/hardware_architecture.md`](docs/hardware_architecture.md).

- **Main Header (`0x00..0x0F`, 16 bytes):**
  - `uint16` format flags (`0x0002` digital-only, `0x0012` analog/widgets), `uint16 0xFFFF`, `uint32 preview_offset`, `uint16 280`, `uint16 280`, `uint16 digit_table_offset`, `uint16 layout_offset`.
- **Layout Stream Elements (back-to-front, terminated by `0x0000`):**
  - `01 00` — Static image (`466×466` background or overlay cap)
  - `01 02` — 4-digit digital clock `(x1, y1 .. x4, y4)` referencing digit table `01 01`
  - `01 12 06 0b` — 11-frame battery progress (`0%..100%`)
  - `01 04 01` — 7-frame weekday (`SUN..SAT`)
  - `01 0a <0|1|2>` — 60Hz rotating analog Hour (`0`), Minute (`1`), and Second (`2`) hands pivoted around `(233, 233)`
- **Pixel Codec (ARGB565 + Per-Row RLE):**
  - Each image begins with `height × uint32` row entries: `(row_byte_len << 21) | (row_byte_offset & 0x1FFFFF)`.
  - Each pixel is 3 bytes: `[Alpha, RGB565_hi, RGB565_lo]`.
  - Control byte `c`: if `c & 0x80`, repeat next 3-byte pixel `c & 0x7F` times; else copy `c` literal 3-byte pixels. All image blocks are 4-byte aligned with `0xFF` padding.

---

## Project Layout

```text
haylou-watch4s-watchface-maker/
├── launch_studio.bat                # Launches Haylou Watch 4S Studio (Web UI)
├── make_and_push_noclock.bat        # Drag & drop any image to build + push via ADB
├── requirements.txt                 # Pillow>=9.0.0
├── LICENSE                          # MIT License
├── studio/
│   ├── server.py                    # Local HTTP API & preset manager (Python stdlib)
│   └── index.html                   # Visual multi-layer Watch 4S designer UI
├── scripts/
│   ├── watchface_compiler.py        # Unified multi-layer .bin compiler & preview engine
│   ├── watchface_bin_maker.py       # Standalone digital / pure-image .bin CLI
│   ├── omnitrix_watchface_maker.py  # Ben 10 Omnitrix generator (4 styles + custom hex)
│   ├── watchface_image_prepper.py   # 466x466 cropper & round bezel previewer
│   ├── patch_and_build_apk.py       # Automated Haylou Fun APK patcher (sideload + capture)
│   └── install_to_phone.bat         # One-click ADB installer
├── docs/
│   ├── haylou_watch4s_customizer_guide.md
│   ├── protocol_specs.md
│   └── hardware_architecture.md
└── samples/
    ├── sample_test_466x466.png
    ├── sample_test_round_preview.png
    └── omnitrix_af_green_preview.png
```

---

## Disclaimer

This is an independent community project not affiliated with Dongguan Liesheng Electronic Co., Ltd. (Haylou). No proprietary APKs, firmware, or copyrighted assets are included in this repository. Use at your own discretion.

## License

[MIT](LICENSE)
