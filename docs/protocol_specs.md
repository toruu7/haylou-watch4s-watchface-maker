# Haylou Watch 4S (LS26) - BLE Protocol & Watchface Layout Specs

## 1. Overview
The **Haylou Watch 4S** (`LS26`, deviceCode `02_A6`) communicates over Bluetooth Low Energy (BLE) using the MoYoung / CRREPA protocol stack (`com.crrepa.ble`) running on top of a **JieLi JL7012A7** dual-core MCU.

Unlike older smartwatches (e.g. Haylou RS4 Plus with Realtek MCU) which pack fonts, background images, and layout JSON into single binary firmware containers (`.bin`), the Watch 4S separates watchface deployment into two distinct stages:
1. **Background Image Transfer:** Native JieLi bitmap streamer (`libjl_bmp_convert.so` -> `707_photo_watch_face.bin`).
2. **Dynamic MCU Layout Control:** Real-time BLE layout command (`0xB4` via `CRPJieliWatchFaceLayoutInfo`).

---

## 2. Command 0xB4: Watchface Layout Control

Dispatched through `Lcom/crrepa/f/a2;->a(Lcom/crrepa/ble/conn/bean/CRPWatchFaceLayoutInfo;)[B`:

```java
// Underlying Dalvik invocation:
c2.a(0xB4, layoutByteArray);
```

### 30-Byte Layout Buffer Structure:
```
Offset  Length  Type    Description                     Values
---------------------------------------------------------------------------------
0x00    1       byte    Command Header Type             0x26 (38)
0x01    1       byte    Sub-command / Version           0x03 (3)
0x02    1       byte    Show Pointer / Analog Hands     0x00 = Disabled, 0x01 = Enabled
0x03    1       byte    Element Array Count (N)         0x00 = No widgets/clock
0x04..  N * 4   bytes   Element coordinates (x, y, id)  Widget descriptors
...     pad     bytes   Zero padding to 30 bytes        0x00
```

### Clock Suppression Patch (Zero Elements):
When `showPointer = 0x00` and `elementCount = 0x00`, the MCU's graphics pipeline skips rendering:
- Analog clock hands
- Digital time digits (hours, minutes, seconds)
- Date, battery percentage, step counter widgets
**Result:** The AMOLED display renders 100% pure custom wallpaper background image without obstruction.

---

## 3. Background Image Stream: JieLi 707N Photo Dial Format

The companion app converts custom gallery photos into JieLi display stream chunks using native library `libjl_bmp_convert.so`:
- **Image Dimensions:** `466 x 466` pixels (Round AMOLED).
- **Target Mode:** `TYPE_707N_RGB_NO_PACK` (`format = 1`).
- **Intermediate File:** `707_photo_watch_face.bin`.
- **Transmission:** Chunked BLE transfer with CRC verification sent to watch flash storage dial slot.

---

## 4. Facebook SDK Key Hash Bypass Spec

In release builds, Facebook SDK calls `FacebookSdk.getApplicationSignature(Context)` which extracts the app's signing certificate SHA-1 and base64 encodes it.
- **Haylou Release Key SHA-1:** `5075681330d7227058adbd281a9b98a9d5b5555e`
- **Base64 Hash:** `UHVvEzDXInBYrb0oGpukqdW1VV4=`
- **Patch Implementation:** Overwritten Dalvik bytecode constructs this exact String and returns it immediately. To satisfy Android 14 ART Bytecode Verifier, `tries_size` is zeroed out and `insns_size` is sized to 104 words (208 bytes) to match the consecutive DEX object boundary at offset `5044204`.

---

## 5. Native Watch 4S (`LS26`) `.bin` Watchface Container Specification

Verified across **210 / 210** official Haylou Watch 4S (`LS26001`) cloud watchfaces (`0` unknown bytes).

### 5.1 16-Byte Main Header (`0x00..0x0F`, `<HHIHHHH`)
| Offset | Size | Type | Field | Notes |
| --- | --- | --- | --- | --- |
| `0x00` | 2 | `u16` | `flags` | Highest layout opcode ID used in the dial (e.g. `0x0002`, `0x000a`, `0x000f`, `0x0012`, `0x0018`, `0x0023`, `0x002e`). |
| `0x02` | 2 | `u16` | `magic` | Always `0xFFFF`. |
| `0x04` | 4 | `u32` | `preview_off` | Byte offset to the `280×280` RLE thumbnail sprite at the end of the file. |
| `0x08` | 2 | `u16` | `preview_w` | Always `280` (`0x0118`). |
| `0x0A` | 2 | `u16` | `preview_h` | Always `280` (`0x0118`). |
| `0x0C` | 2 | `u16` | `dt_off` | Resource/digit-table start offset (`0x0010`, or `0x0000` if no digit tables or animation header). |
| `0x0E` | 2 | `u16` | `lo_off` | Layout opcode stream start offset (immediately after the `00 00` resource-table terminator). |

### 5.2 Resource & Digit Font Table Section (`dt_off .. lo_off`)
- **Optional Animation Descriptor (`00 02`, 8 bytes):** Required at `dt_off = 0x10` immediately before the first digit table whenever animated opcodes (`01 2e` or `01 1a`) are present:
  ```
  00 02 00 00 00 02 01 00
  ```
  Across all 211 official Watch 4S (`LS26`) dials, whenever this prefix is emitted at `0x10`, at least one digit table (`DT#0`) follows before the `00 00` terminator (for analog-only `01 1a` / `01 2e` dials without digital numbers, the compiler emits a tiny transparent `4×4` dummy `DT#0`).
- **Multiple Digit Font Tables (`01 01 <id>`, 83 bytes each):** Watch 4S supports multiple independent digit sets (`DT#0..DT#N`), allowing Clock, Date, Seconds, Steps, Heart Rate, Calories, Distance, and Battery % to each use distinct fonts, sizes, and colors:
  - Header (3 bytes): `0x01, 0x01, table_id` (`0, 1, 2, ...`)
  - 10 glyph descriptors (`80` bytes): `10 × <IHH` (`offset:u32, w:u16, h:u16`) for digits `0` through `9`.
- **Terminator:** `00 00` (2 bytes) immediately preceding `lo_off`.

### 5.3 Layout Stream Opcodes (`lo_off .. data_start`, terminated by `00 00`)
All sprite coordinates are top-left `(x, y)` on the `466×466` display unless noted. Dynamic number alignment byte `align`: `0` = Left, `1` = Right, `2` = Center.

| Opcode | Length | Struct (`<...`) | Function |
| --- | --- | --- | --- |
| `01 00` | 14 B | `BBHHIHH` | **Static Image / Background:** `x, y, off, w, h` |
| `01 02` | 34 B | `BBBBBB HHHHHHHH HHIHH` | **Digital Clock (`HH:MM`):** `dtH1, dtH0, dtM1, dtM0`, 4 digit coords `(x,y)`, optional blinking colon `(cx, cy, coff, cw, ch)` (12 zero bytes if omitted) |
| `01 04` | `7 + N×8` B | `BBBHH + N×IHH` | **Weekday:** `sub=1` (`7` EN frames SUN..SAT), `sub=2` (`14` frames: 7 EN + 7 CN) |
| `01 05` | 19 B | `BBHHIHH 5B` | **Dynamic Battery Bar:** frame sprite + inner fill box `(padX, padY, fillW, fillH, style)` |
| `01 06` | 26 B | `BBBBHH + 18×0` | **Live Heart Rate (BPM):** `dt_idx, align, x, y` (optionally preceded by `01 23` dash glyph for `--`) |
| `01 07` | 26 B | `BBBBHH + 18×0` | **Live Steps:** `dt_idx, align, x, y` |
| `01 08` | 42 B | `BBBBHH + 24×0 + IHHH` | **Live Distance (`km/mi`):** `dt_idx, align, x, y`, decimal-point glyph `(dot_off, dot_w, dot_h, 0)` |
| `01 09` | 17 B | `BBBBHH + 9×0` | **Live Calories (`Kcal`):** `dt_idx, align, x, y` |
| `01 0a` | 19 B | `BBBHHIHHHH` | **Analog Hand:** `id` (`0`=Hour, `1`=Min, `2`=Sec), `x, y, off, w, h, pivot_x, pivot_y` (`233,233` or `0xFFFF,0xFFFF` for center) |
| `01 0d` | 12 B | `BBBBHHHH` | **Live Day (`DD`):** `dt_d1, dt_d0, x1, y1, x2, y2` |
| `01 0e` | 198 B | `BBHH + 24×IHH` | **Month Name String (`JAN..DEC`):** `x, y`, 12 EN + 12 CN/zero slots |
| `01 0f` | 12 B | `BBBBHHHH` | **Live Month (`MM`):** `dt_m1, dt_m0, x1, y1, x2, y2` |
| `01 10` | `3+5N` B | `BBB + N×B + N×HH` | **Live Year (`YYYY`):** `n=4`, 4 `dt` indices + 4 coords |
| `01 11` | 27 B | `BBBHHHH + 2×IHH` | **AM / PM Indicator:** `sub=1`, `(x1, y1, x2, y2)`, AM sprite, PM sprite |
| `01 12` | `8+N×8` B | `BBBBHH + N×IHH` | **Multi-Frame Progress / Gauge (`N=11` for `0%..100%`):** `sub=0x00` Steps, `0x02` Calories, `0x03` Distance, `0x05` Active/HR, `0x06` Battery |
| `01 14` | 23 B | `BBBHH + 2×IHH` | **Bluetooth Status (2-state):** `sub=0`, `x, y`, `s0` = disconnected sprite, `s1` = connected sprite |
| `01 15` | 8 B | `BBBBHH` | **Live Battery Percentage (`0..100`):** `dt_idx, align, x, y` |
| `01 18` | 12 B | `BBBBHHHH` | **Live Seconds (`SS`):** `dt_s1, dt_s0, x1, y1, x2, y2` |
| `01 1a` | `8+N×8` B | `BBBBHH + N×IHH` | **Multi-State Art / Tap-Switch Frame:** `sub=0, cnt, x, y` + `cnt` sprites (requires 8-byte `00 02` animation prefix at `0x10`) |
| `01 1b` | `7+N×8` B | `BBBHH + N×IHH` | **Weather Icon (`N=9`):** `0`=Partly Cloudy, `1`=Fog/Mist, `2`=Cloudy, `3`=Rain, `4`=Snow, `5`=Sunny/Clear, `6`=Wind/Dust, `7`=Haze/Smog, `8`=Unknown |
| `01 1c` | 32 B | `BBBBHH + 3×IHH` | **Temperature:** `dt_idx, align, x, y`, minus, `°C`, `°F` sprites |
| `01 1d` | 3 B | `BBB` | **Color/Style Group Tag:** `group_id` |
| `01 1f` | 22 B | `BBHH + 2×IHH` | **Distance Unit (`km`/`mi`):** `x, y`, km sprite, mi sprite |
| `01 23` | 10 B | `BBIHH` | **No-Data Dash / Glyph Descriptor:** `(off, w, h)` placed before `01 06`/`01 07` (`--` glyph) or `1×1` sentinel at layout start |
| `01 25` | 26 B | `BBBBHH + 16×0 + BB` | **Live SpO2 (%):** `dt_idx, align, x, y` |
| `01 2e` | `15+N×4` B | `BBBBBBBHHHH + N×I` | **Hardware Animated Sprite / GIF Loop:** `mode=0, frame_count, loop=0, autoplay=1, interval` (`~15` for 4–6 FPS multi-frame, `24` for 2-frame), `x, y, w, h`, followed by `frame_count` `u32` RLE sprite offsets |

### 5.4 Sprite RLE Encoding (Row-Indexed RGBA565A8)
- Row index table (`h × 4` bytes, `<I` per row): `entry = ((row_len & 0x7FF) << 21) | (row_off_rel & 0x1FFFFF)`.
- Each pixel is 3 bytes: `[alpha:u8, rgb565_hi:u8, rgb565_lo:u8]` (big-endian RGB565).
- Control byte `c`:
  - `c & 0x80 != 0`: repeat next 3-byte pixel `c & 0x7F` times (max 127).
  - `c & 0x80 == 0`: literal run of `c` pixels (`c × 3` bytes, max 127).
- All sprite blocks are 4-byte aligned. Total `.bin` file size should remain under **1.3 MB** (`~1,310,720` bytes) for Watch 4S flash budget safety.

