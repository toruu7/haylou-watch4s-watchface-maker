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
