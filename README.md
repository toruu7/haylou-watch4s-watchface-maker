# Haylou Watch 4S Watchface Studio & `.bin` Maker

An open-source visual watchface designer, native binary (`.bin`) compiler, and ADB sideloader for the **Haylou Watch 4S** (`LS26` / `02_A6` · JieLi `JL7012A7` · `466×466` Round AMOLED).

Overcomes the default Haylou Fun companion app limitations—fixed clock placements, fixed fonts, and inability to hide the clock—by compiling **genuine JieLi / MoYoung ARGB565-RLE `.bin` watchfaces** and installing them through the watch's official cloud dial slot.

![Watch 4S Studio Designer](docs/screenshots/studio_designer.png)

![Watchface Showcase](docs/screenshots/watchface_showcase.png)

<details>
<summary><strong>View Watch Face Gallery Screenshot</strong></summary>

![Watch 4S Studio Gallery](docs/screenshots/studio_gallery.png)

</details>

---

## Features

- **Visual Multi-Layer Watchface Studio (`launch_studio.bat`):**
  - Local dark-mode browser UI with a machined Watch 4S hardware preview (`466×466` pixel-exact rendering), live **`.bin` flash-budget & opcode checker**, and **True Z-Order Layer Stack** (drag or `↑`/`↓` reorder layers matching exact back-to-front `.bin` opcode emission).
  - **Direct 1:1 drag-and-drop positioning** for every widget, sticker, text label, GIF zone, and telemetry sensor on the watch face with magnetic center-snap guides, arrow-key nudging, and live coordinate HUD.
  - **Saved Presets Library:** Save, edit (with full asset re-hydration), duplicate, delete, export/import `.face.zip` packages (including all uploaded assets), import `.bin` files, and push any preset to your phone over ADB in one click.
- **Tap-to-Switch Multi-Scene / Theme Art (`01 1a`):**
  - Tap your watch screen to cycle between 2–6 interactive scenes: **Day/Night gradient themes**, **Ben 10 Omnitrix themes**, or **custom uploaded artwork**, with a live **"Tap Scene" preview tester** built into Studio.
- **Procedural Bezel & Index Tick Generator (`01 00`):**
  - 8 crisp 2×-supersampled bezel styles (**Minimal Dots**, **Classic Baton**, **Diver Watch Indices**, **Roman Numerals**, **Arabic Numerals**, **Motorsport Tachymeter**, **Neon Rings**, and **Tactical Radar HUD**) with primary/accent colors, inset, opacity, glow, and optional minute sub-ticks.
- **Pure Image Mode (No Clock):**
  - Full-resolution `466×466` custom artwork with **zero clock digits, zero date, and zero widgets**.
- **Pro Digital Clock & Typography:**
  - Horizontal (`HH:MM` with optional **native blinking colon**) or **Stacked Vertical** (`HH` over `MM`) layouts.
  - Optional **Live Seconds (`01 18`)** and **AM / PM Indicator (`01 11`)** with independent color, size, and placement.
  - Upload any custom `.ttf` or `.otf` font directly in the Studio UI.
  - Vertical color gradients, stroke/outline, neon outer glow, and custom spacing.
- **Multi-Zone Animated GIF / WebP Dials (`01 2e`):**
  - Drop animated `.gif` or `.webp` files as full-screen backgrounds or stack up to **3 independent floating GIF zones** at any Z-order with live animated browser preview and automatic `1.3 MB` flash-budget optimization.
- **60Hz Rotating Analog Hands (`01 0a`) — Procedural & Custom PNG Uploads:**
  - 7 built-in hand packs (**Omnitrix**, **Stark Arc Reactor**, **Skeleton Dauphine**, **8-Bit Pixel**, **Classic Needles**, **Neon Pointers**, **Minimalist Baton**) **plus Custom PNG Hand & Center Cap Uploads** with adjustable lengths and pivot tail %.
- **Custom PNG Stickers & Text Labels (`01 00`):**
  - Layer transparent PNG badges, logos, or HUD frames (with scale, rotation, opacity) and custom gradient/glow text labels anywhere in the Z-order stack.
- **Full Native Watch 4S Widgets (Verified Byte-for-Byte Across Official LS26 Dials):**
  - **Live Weather Icon (`01 1b`, 9 states) & Live Temperature (`01 1c`, `-`/`°C`/`°F`):** Full color, monochrome, or neon icons with live condition preview (`Sunny`, `Partly Cloudy`, `Cloudy`, `Rain`, `Snow`, `Fog`, `Wind`, `Haze`, `Unknown`).
  - **Bluetooth Status Badge (`01 14`):** 2-state disconnected/connected indicator in 4 styles (`BT Rune`, `Pill Badge`, `Link Chain`, `Dot Ring`).
  - **Richer Live Date & Year (`01 0e` / `01 0f` / `01 0d` / `01 10`):** `MON DD`, `DD MON`, `MON` (12-frame `JAN`–`DEC` month names), `MM/DD`, `DD/MM`, `MM-DD`, `DD-MM`, or `DD`, plus optional **4-Digit Year (`YYYY`)**.
  - **Live Health Telemetry:** Steps (`01 07`), Heart Rate BPM (`01 06` + `01 23` `--` dash glyph), Calories Kcal (`01 09`), Distance (`01 08` with baseline decimal dot + dynamic **`01 1f` `km`/`mi` unit label**), and Battery % (`01 15`), with Left/Right/Center alignment and optional mini metric icons.
  - **Multi-Gauge Stacking (`01 12`) & Native Battery Fill Bar (`01 05`):** Stack up to **4 simultaneous gauges** (Outer Ring, Inner Ring, Top/Bottom/Left/Right Curved Arcs, Horizontal Bar, Pill Icon, or Hardware-Clipped Native Battery Fill Bar `01 05`) across Battery, Steps, Calories, Distance, and Active Minutes.
  - **7-Frame Weekday Label (`01 04` `SUN`–`SAT`):** Custom font, color, uppercase toggle, and draggable position.
- **Zero-Java Pure-Python Haylou Fun APK Patcher (`scripts/patch_and_build_apk.py`):**
  - Modular CLI patches (`--noclock`, `--unlock-cards`, `--rhr`, `--vitality-vo2`, `--night-raise-to-wake`, `--cycling-fixes`, `--workout-analytics`, `--hrv-active`, `--hourly-charts`, `--voip-calls`, `--all`) with pure-Python 4-byte/4KB alignment and APK Signature Scheme v2 & v3 signing (`cryptography`) — **no Java, `keytool`, `zipalign`, or Android SDK Build-Tools required**.
  - Unlocks hidden Watch 4S health cards & firmware-verified BLE controls (PAI, VO2 Max, HRV, Active/Standing Hours, High/Low Heart Rate Alert `0x87 02`, and Daytime Sleep Naps `0xBC 01`), unlocks Watch 4S's native **30-minute hardware step histograms (`0x59`)** plus **Hourly Steps, Calories & Exercise Day Charts** across Daily Activities, Steps/Calories `D` tabs, and Home mini cards, adds a 3rd **Resting Heart Rate** card to Heart Rate Details, runs on-device **Vitality Score (PAI)**, **VO2 Max**, **Workout Analytics** (Aerobic & Anaerobic Training Effect `0.2–5.0`, Exercise Load / EPOC, Recovery Time, and Per-Workout VO2 Max in `SportDetailActivity`), **30-Minute Stress-Derived HRV**, and **Hourly Active / Standing Hours (12h)** engines, unlocks a **Night Raise-to-Wake Schedule** (**Device settings → DND mode**, wired exclusively to BLE `0x72` `sendQuickViewTime` so wrist-wake turns off at night, default `23:00–07:00`, while calls & notifications stay active), adds **Cycling Fixes** (strips handlebar-vibration phantom cycling steps using exact Watch 4S `0x59` 30-min hardware overlap—persisted across midnight in local-only `SportTable.sportcounter`—with a `30 steps/min` historical fallback and lossless self-healing while preserving bike distance/calories, computes true moving time & moving average speed on synced GPS rides while keeping `SportTable.points` intact for Strava's smooth velocity curve, and adds live GPS auto-pause/auto-resume for phone-started rides), and adds **VoIP Incoming Call Alerts + Wrist Reject** (WhatsApp, WhatsApp Business, Messenger, Instagram, Telegram, Viber, and Discord ring Watch 4S with the real caller name via BLE `0x41` and execute the VoIP app's Decline action when rejected from the wrist).
- **Ben 10 Omnitrix Generator:**
  - 4 built-in series faceplates (**Alien Force / UAF**, **Original Series**, **Omniverse**, **5 Years Later**) with 6 preset colorways + full custom hex color picker and glow control.
- **Safe & 100% Reversible:**
  - Installs strictly into the watch's official cloud dial slot (`CRPWatchFaceInfo.WacthFaceType.JIELI`). Never flashes firmware or bootloaders. Switching watchfaces on the watch restores stock dials immediately.

---

## Requirements

- **Python 3.9+**, **Pillow 10.2+**, and **cryptography 41+** (`pip install -r requirements.txt`)
- **Android Debug Bridge (`adb`)** in your `PATH` (or Android SDK platform-tools) + Android phone with **USB Debugging** enabled
- Your own copy of the official **Haylou Fun v4.0.8 APK** *(not redistributed in this repository; zero Java/SDK build-tools needed!)*

---

## Getting Started

### 1. Clone & Install Python Dependencies
```bash
git clone https://github.com/toruu7/haylou-watch4s-watchface-maker.git
cd haylou-watch4s-watchface-maker
pip install -r requirements.txt
```

### 2. Patch & Install Haylou Fun (One-Time Pure-Python Setup)
Obtain the official `haylou-fun-v4-0-8.apk`, then run the zero-dependency pure-Python patcher. It applies all DEX patches, aligns `resources.arsc` (4-byte) and `.so` libraries (4 KB page-aligned), auto-generates a pure-Python RSA-2048 PKCS#12 keystore if missing, and signs with APK Signature Scheme v2 & v3:

```bash
# Full suite (watchface sideload + FB bypass + card/BLE unlocks + Resting HR + Vitality PAI & VO2 Max + Workout Analytics + Hourly Charts + HRV & Active Hours + Night Raise-to-Wake + Cycling Fixes + VoIP Calls):
python scripts/patch_and_build_apk.py --src /path/to/haylou-fun-v4-0-8.apk --all

# Custom default night-off window for Raise-to-Wake (default: 23:00-07:00 -> active 07:00-23:00):
python scripts/patch_and_build_apk.py --src /path/to/haylou-fun-v4-0-8.apk --all --night-hours 22:30-06:30

# Or pick individual modular patches:
python scripts/patch_and_build_apk.py --src /path/to/haylou-fun-v4-0-8.apk --noclock
python scripts/patch_and_build_apk.py --src /path/to/haylou-fun-v4-0-8.apk --noclock --unlock-cards --rhr --vitality-vo2 --workout-analytics --hourly-charts --hrv-active --night-raise-to-wake --cycling-fixes --voip-calls
```

Connect your Android phone via USB and install the generated APK:
```bash
adb install -r haylou-fun-v4-0-8-full-health.apk
```
> **Important:** Open Google Play Store &rarr; **Haylou Fun** &rarr; **⋮** &rarr; **uncheck "Enable auto update"** so Play Store does not overwrite your patched build.

### 3. Launch Haylou Watch 4S Studio
- **Windows:** Double-click `launch_studio.bat`
- **macOS / Linux:** `./launch_studio.sh` (or `python3 studio/server.py`)

Your browser will open at **http://127.0.0.1:8466**. If the port is busy, set
`STUDIO_PORT=8467`; set `STUDIO_LOG=1` to log requests to the terminal.

On first launch an inline guide walks you through the four-step workflow. You can
reopen it with the **?** button in the title bar. Dials can be exported and shared as
single `.face.zip` packages and imported again from the Gallery.

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
  - `uint16` format flags (highest layout opcode ID: `0x0002` digital-only, `0x0012` gauges, `0x0018` seconds, `0x0023` telemetry dash, `0x002e` animated GIF), `uint16 0xFFFF`, `uint32 preview_offset`, `uint16 280`, `uint16 280`, `uint16 digit_table_offset`, `uint16 layout_offset`.
- **Resource & Multiple Digit Font Tables (`dt_off..lo_off`, terminated by `00 00`):**
  - Optional 8-byte animation header (`00 02 00 00 00 02 01 00`) when `01 2e` / `01 1a` animations are present, followed by one or more 83-byte digit tables (`01 01 <id>` + `10 × <IHH`).
- **Layout Stream Elements (back-to-front Z-order, terminated by `0x0000`):**
  - `01 00` — Static image (`466×466` background, procedural bezel/ticks, PNG stickers, custom text labels, date separator, or hand cap)
  - `01 2e` — Hardware animated multi-frame sprite / GIF loop (1–3 independent zones: `mode, count, loop, autoplay, interval, x, y, w, h, offsets[]`)
  - `01 1a` — Tap-to-Switch multi-scene / theme art (2–6 frames cycled on watch tap)
  - `01 02` — 4-digit digital clock (34 B: 4 digit coords + optional 12-byte blinking colon sprite)
  - `01 18` — Live seconds (`SS`) · `01 11` — AM/PM indicator
  - `01 0f` / `01 0d` / `01 0e` / `01 10` — Live month (`MM`), day (`DD`), 12-frame month name (`JAN`–`DEC`), and 4-digit year (`YYYY`)
  - `01 1b` / `01 1c` — Live 9-state Weather icon & Temperature (`-` / `°C` / `°F`)
  - `01 14` — 2-state Bluetooth connection badge (`s0`=disconnected, `s1`=connected)
  - `01 06` / `01 07` / `01 08` / `01 09` / `01 15` / `01 1f` — Live Heart Rate BPM (with `01 23` `--` dash), Steps, Distance (with `.` dot + dynamic `km`/`mi` unit), Calories Kcal, and Battery %
  - `01 12` / `01 05` — 11-frame stackable progress gauges (`sub`: `0x06` Battery, `0x00` Steps, `0x02` Calories, `0x03` Distance, `0x05` Active) + native hardware-clipped dynamic battery fill bar
  - `01 04 01` — 7-frame weekday (`SUN..SAT`)
  - `01 0a <0|1|2>` — 60Hz rotating analog Hour (`0`), Minute (`1`), and Second (`2`) hands (procedural or custom PNG) pivoted around `(233, 233)`
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

This is an independent community project not affiliated with Dongguan Liesheng Electronic Co., Ltd. (Haylou). No proprietary APKs, firmware, or copyrighted assets are included in this repository. Ben 10 / Omnitrix and Fallout / Pip-Boy are trademarks of their respective owners; their names are used here descriptively for fan-made dial templates, with no endorsement or affiliation. Use at your own discretion.

## License

[MIT](LICENSE)
