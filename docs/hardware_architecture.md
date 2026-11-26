# Haylou Watch 4S (`LS26`) - Hardware & Architecture Teardown

## 1. Device Hardware Identification

| Property | Value |
| :--- | :--- |
| **Model Name** | Haylou Watch 4S |
| **Model Code** | `LS26` (Codename: `Nadal`) |
| **Internal DeviceCode** | `02_A6` |
| **FCC ID** | `2AMQ6-HF012` |
| **Manufacturer** | Dongguan Liesheng Electronic Co., Ltd. |
| **Display Panel** | 1.43" Round AMOLED (`466 × 466` pixels, ~461 PPI, 60Hz) |
| **Main SoC / MCU** | **Zhuhai JieLi JL7012A7** (`AC701N` / `br28` family) |
| **CPU Architecture** | Dual-core 32-bit RISC MCU (System Core + DSP Graphic Core) |
| **RAM** | Embedded high-speed PSRAM |
| **Storage** | 16 MB SPI NOR Flash (`~960 KB` reliable watchface transfer budget) |
| **Sensors** | Optical PPG Heart Rate / SpO2 / Stress, 3-Axis Accelerometer, Geomagnetic |
| **Connectivity** | Bluetooth 5.3 (BLE + Classic Audio BT for calling) |
| **Companion App** | Haylou Fun (`com.yingsheng.hayloufun`) |
| **Protocol Stack** | MoYoung / CRREPA BLE stack (`com.crrepa.ble`) |

---

## 2. Two Watchface Pipelines on Watch 4S

The Watch 4S supports two distinct watchface mechanisms over BLE:

1. **Photo Dial Slot (`707_photo_watch_face.bin` + `0xB0`/`0xB4`):**
   Streams a `466×466` background converted by `libjl_bmp_convert.so` alongside a dynamic layout packet (`0xB0` / `0xB4`) controlling built-in MCU clock/widget overlays.
2. **Native Cloud Dial Slot (`ls25plate.bin` — used by Watch 4S Studio):**
   Streams a self-contained **JieLi / MoYoung ARGB565-RLE `.bin` container** into the watch's official cloud dial slot (`CRPWatchFaceInfo.WacthFaceType.JIELI`). Supports custom fonts, 60Hz analog hands (`01 0a`), tap-to-switch scenes (`01 1a`), animated GIF/WebP sprites (`01 2e`), live weather (`01 1b`/`01 1c`), Bluetooth status (`01 14`), multi-gauge rings (`01 12`), and all live health telemetry (`01 06`–`01 15`). See [`docs/protocol_specs.md`](protocol_specs.md) for the complete opcode specification.

---

## 3. Architectural Comparison: Watch 4S vs RS4 Plus

| Feature | Haylou RS4 Plus (`LS11`) | Haylou Watch 4S (`LS26`) |
| :--- | :--- | :--- |
| **Form Factor** | Rectangular (`368 × 448`) | **Round (`466 × 466`)** |
| **Processor Platform** | Realtek `RTL8762DW` (ARM Cortex-M4F) | **JieLi `JL7012A7`** (Dual-core 32-bit RISC) |
| **Cloud Dial Format** | Realtek packed `.bin` + JSON layout | **MoYoung / JieLi ARGB565-RLE `.bin`** (`0xFFFF` header + binary opcode stream `01 00`–`01 2e`) |
| **Photo Dial Format** | Static background + MCU clock | Streamed JieLi 707N bitmap + dynamic BLE layout (`0xB0`/`0xB4`) |
| **Brick Risk** | Moderate if bootloader/header is malformed | **Zero Risk (Safe)**: Installed strictly through the official cloud dial slot; never touches firmware or bootloader |
