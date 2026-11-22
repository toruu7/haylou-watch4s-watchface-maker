# Haylou Watch 4S (LS26) - Hardware & Architecture Teardown

## 1. Device Hardware Identification

| Property | Value |
| :--- | :--- |
| **Model Name** | Haylou Watch 4S |
| **Model Code** | `LS26` |
| **Internal DeviceCode** | `02_A6` |
| **FCC ID** | `2AMQ6-HF012` |
| **Manufacturer** | Dongguan Liesheng Electronic Co., Ltd. |
| **Display Panel** | 1.43" Round AMOLED (466 x 466 pixels, ~461 PPI, 60Hz) |
| **Main SoC / MCU** | **Zhuhai JieLi JL7012A7** (AC701N / br28 family) |
| **CPU Architecture** | Dual-core 32-bit RISC MCU (System Core + DSP Graphic Core) |
| **RAM** | Embedded high-speed PSRAM |
| **Storage** | 16 MB SPI NOR Flash |
| **Sensors** | Optical PPG Heart Rate/SpO2, 3-Axis Accelerometer, Geomagnetic |
| **Connectivity** | Bluetooth 5.3 (BLE + Classic Audio BT for calling) |
| **Companion App** | Haylou Fun (`com.yingsheng.hayloufun`) |
| **Protocol Stack** | MoYoung / CRREPA BLE stack (`com.crrepa.ble`) |

---

## 2. Architectural Comparison: Watch 4S vs RS4 Plus

A common point of confusion is comparing the **Haylou Watch 4S** with the **Haylou RS4 Plus** (which has an open-source watchface maker repository like `RikzDev/Haylou-rs4-plus-watchface-maker`).

| Feature | Haylou RS4 Plus (`LS11`) | Haylou Watch 4S (`LS26`) |
| :--- | :--- | :--- |
| **Form Factor** | Rectangular (368 x 448) | **Round (466 x 466)** |
| **Processor Platform** | **Realtek RTL8762DW** (ARM Cortex-M4F) | **JieLi JL7012A7** (Dual-core 32-bit RISC) |
| **Watchface Format** | Packed `.bin` container containing header, image slices, font tables, and JSON layout table. | **Streamed JieLi 707N bitmap** + dynamic BLE runtime layout command (`0xB4`). |
| **Clock Rendering** | Baked into dial binary layout structure. | **Rendered dynamically in real time by MCU graphics pipeline**. |
| **Modding Strategy** | Unpack `.bin`, replace PNGs, recompile binary. | **Patch companion app BLE command buffer to suppress clock digits**. |
| **Brick Risk** | Moderate (corrupted `.bin` header can hang dial load). | **Zero Risk (Safe)**: Transferred via official photo dial protocol slot; never touches firmware or bootloader. |
