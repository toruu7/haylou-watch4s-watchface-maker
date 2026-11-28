# Haylou Watch 4S (`LS26` / `JL7012A7`) — OTA Firmware Reverse Engineering Teardown

Complete static reverse engineering notes for the **Haylou Watch 4S** (`LS26`, internal model `MOY-7NP2-2.0.0`, `deviceCode 02_A6`, serial prefix `LS262QW5313100000`) based on official OTA firmware `V24.28.001.1.1.1.1.38`.

> **Legal / Safety Note:** No proprietary firmware binaries (`.ufw`, `.bin`, `.zip`) are distributed in this repository. Use [`scripts/jieli_fw_unpacker.py`](../scripts/jieli_fw_unpacker.py) on your own locally obtained `.ufw` OTA image to reproduce every table below and verify CRC16 integrity.

---

## 1. JieLi `JL701N` (`AC701N`) `.ufw` & SPI Flash Encryption

### 1.1 UFW Archive Container Layout
The Watch 4S OTA file (`V24.28.001.1.1.1.1.38.ufw`, `1,847,360 B`) uses JieLi's encrypted UFW format:
- **Main Header (`0x000..0x03F`, 64 bytes):** Encrypted with JieLi's 16-bit CRC16-CCITT (`0x1021`) LFSR XOR stream using seed `0xFFFF`.
  - Contains `hdr_crc` (`u16`), `ver` (`0x1F2E`), `total_size` (`1,847,360`), `part_count` (`9`), and chip tag `"JL701N"`.
- **Part Directory (`0x040`, `9 × 80` bytes = `0x2D0` bytes):** Each 80-byte entry is individually encrypted with the `0xFFFF` LFSR stream and describes an embedded file (`flash.bin`, `uboot.version`, `isd_config.ini`, `v_ota.bin`, `ota.bin`, `farg.cfg`, `blimit.bin`, etc.) with `type`, `data_crc`, `offset`, `length`, and 16-byte ASCII filename at entry offset `+0x40`.

### 1.2 SPI NOR Flash (`JLFS`) & 32-Byte SFC Hardware XOR Cipher
Inside the UFW's `flash.bin` (`1,830,912 B`, `NEW_FLASH_FS = YES`):
- **Root `JLFS` Table (`0x0000..0x009F`, 32-byte entries):** Encrypted with LFSR seed `0xFFFF`. Contains:
  - `0x0020`: `uboot.boot` (`@ 0x0000A0`, `3,666 B`)
  - `0x0040`: `isd_config.ini` (`@ 0x000EF2`, `171 B`, compact binary config)
  - `0x0060`: `app_dir_head` (`@ 0x001000`, `len = 0xFFFFFFFF`, app partition root)
  - `0x0080`: `key_mac` (`@ 0xFFF000`, `4,096 B`)
- **App Partition (`app_dir_head @ 0x1000`, `app.bin`, `cfg_tool.bin`):** Encrypted with JieLi's **32-byte SPI Flash Cache (SFC) XOR-LFSR cipher**:
  $$\text{seed}(\text{flash\_off}) = \texttt{0x1607} \oplus \left(\frac{\text{flash\_off} - \texttt{0x1000}}{4}\right) \pmod{2^{16}}$$
  For each 32-byte aligned block, initialize `crc = seed` and for each byte `i`:
  ```python
  out[i] = data[i] ^ (crc & 0xFF)
  crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else ((crc << 1) & 0xFFFF)
  ```
- **Bit-Exact Verification:**
  - `app.bin`: `1,628,496 B` → decrypted `CRC16 = 0xA19F` (**exact match** with `app_dir_head`), `13,116` ASCII strings.
  - `cfg_tool.bin`: `935 B` → decrypted `CRC16 = 0x9AD7` (**exact match** with `app_dir_head`).

### 1.3 `app.bin` Runtime Memory Map (`crt0` at `app.bin+0x000`)
- **XIP Flash Entry Point:** `0x06000120` (`app.bin` maps linearly at `VA = 0x06000120 + file_offset`)
- **SRAM `.data`:** copied from `app.bin+0x185034` → `0x00108040` (`0x3118 B`, holds device strings, battery curve, BLE adv payload, GoMore defaults)
- **SRAM `.bss`:** zero-initialized at `0x0010B160` (`0x189DC B`)
- **SRAM `.ramcode`:** copied from `app.bin+0x18814C` → `0x00123B40` (`0x5804 B`)

---

## 2. Verified Hardware Silicon BOM (Directly from Firmware Drivers)

| Subsystem | Exact Silicon / Driver | Evidence in `app.bin` / `isd_config.ini` |
| :--- | :--- | :--- |
| **Main SoC** | **JieLi `JL7012A7`** (`JL701N` / `AC701N`, SDK `JL701N_V2.2.1`) | Dual-core `pi32v2` CPU + low-power `P11` co-processor |
| **Optical PPG (HR / SpO2)** | **VCare `VC30FS` / `VC30FX`** | `vc30fx_sc`, `xVc30FsErrorCnt > 90`, `s_CheckVc30fId` |
| **GNSS / GPS Receiver** | **ICOE `CC1165W`** (+ **Airoha `AG3352B`** driver) | `icoe_gnss_init`, `AnalyzeCc1165wType`, `gnssSetAg3352bVersion`, `[GNSS EPO]` |
| **Touchscreen Controller** | **ChipSemi `CHSC6x`** | `chsc6x: TP chip_info OK::fw_ver:%d, vendor_id:%d, prj_id:%d` |
| **Accelerometer / Steps** | **`P11` Co-Processor G-Sensor** | `p11 gsensor init`, `p11_algo_event_handle`, `GsensorAlgoHandle` |
| **Battery Charger / PMIC** | **Awinic `AW320xx`** | `AppAw320xxChargingEnable/Disable`, `AppAw320xxRegDataInit` |
| **Battery Voltage Curve** | 12-point LUT (`app.bin+0x18629A`) | `3400, 3613, 3642, 3696, 3725, 3759, 3806, 3868, 3944, 4055, 4162, 4250 mV` |
| **External SPI NOR Flash** | **16 MB Quad-SPI NOR** (`0x1000000`, 4-byte addr) | `EX_FLASH = PC03_1A_NULL`, `EX_FLASH_IO = 4_PC01_PC02_PC04_PC05_PC00`, **`FLASH_WRITE_PROTECT = NO`** |
| **Debug UART Console** | **Pin `PB02` @ `1,000,000 baud` (`1 Mbps`)** | `UTTX = PB02`, `UTBD = 1000000`; crash trace saved to `mnt/sdfile/app/debug` |
| **On-Watch Biometrics** | **Licensed GoMore SDK** | `[GOMORE LOG]`, `healthIndexInitUser`, `CheckGomoreKey`, defaults `[25, 1, 180, 70, 200, 60, 40]` |

---

## 3. Complete 16 MB SPI NOR Flash Partition Map

Extracted from `app_dir_head` (`0x1000`) and the device platform table at `app.bin+0x131064`:

| Partition | Path / Mount | Start Offset | Size | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| `PRCT` | `flash.bin` | `0x000000` | `1,788 KB` (`0x1BF000`) | Bootloader + `app.bin` (`1.63 MB`) + `cfg_tool.bin` |
| `VM` | Internal VM | `0x1BF000` | `252 KB` (`0x3F000`) | Non-volatile user settings, alarms, pairing state |
| `DEBUG` | `mnt/sdfile/app/debug` | `0x1FE000` | `4 KB` (`0x1000`) | Crash dump (`SP/USP/SSP/R0..R15/PC_TRACE`) |
| `BTIF` | `mnt/sdfile/app/btif` | `0x1FF000` | `4 KB` (`0x1000`) | Classic BT & BLE link keys |
| `font_lvgl` | `mnt/sdfile/app/FONT` | `0x200000` | `3,180 KB` (`0x31B000`) | Watch UI fonts |
| `res_nor` (UI/Res) | `storage/res_nor/C/` | `0x51B000` | `~7.2 MB` | UI bitmaps, audio tones, & cloud watchface slots |
| `update_fw` | OTA staging | `0xC50000` | `2,048 KB` (`0x200000`) | Staged `.ufw` OTA image buffer |
| `manager_data` | `mnt/sdfile/EXT_RESERVED/DM` | `0xE50000` | `256 KB` (`0x40000`) | Sport/HR/Step storage + backup GoMore key |
| `system_data` | `mnt/sdfile/EXT_RESERVED/SYS` | `0xE90000` | `128 KB` (`0x20000`) | System data |
| `gnss_data` | `mnt/sdfile/EXT_RESERVED/GNSS` | `0xEB0000` | `1,280 KB` (`0x140000`) | GNSS EPO A-GPS ephemeris & GPS workout tracks |
| `gomore_key` | `mnt/sdfile/EXT_RESERVED/GOMORE` | `0xFF1000` | `4 KB` (`0x1000`) | Primary GoMore license key |
| `key_mac` | `key_mac` | `0xFFF000` | `4 KB` (`0x1000`) | Factory Bluetooth MAC & auth key |

---

## 4. Dual-Core RTOS Task Table (`app.bin+0x0D75F8`)

40 RTOS threads across both `JL7012A7` cores:
- **Core 0 (`32` tasks):** `app_core` (`4 KB`), `sys_event`, `btctrler`, `btencry`, `tws`, `btstack` (`3 KB`), `audio_dec` (`3.2 KB`), `dev_mg`, `usb_msd`, `aec`, `aec_dbg`, `update`, `dw_update`, `uart_update`, `systimer`, `usb_audio`, `plnk_dbg`, `adc_linein`, `enc_write`, `fm_task`, `lcd_init`, `tp_init`, `lcd` (`4 KB`), `effect` (`4 KB`), `xMbs` (`4 KB`), `xHealth` (`4 KB`), `xCommon` (`8 KB`), `xMultityUdt` (`4 KB`), `gnssRecvTask` (`4 KB`), `gnssSendTask` (`4 KB`), `data_export`, `mic_stream`, `audio_vad`.
- **Core 1 (`7` tasks):** `audio_enc`, `ui` (`4 KB`), `imb` (`4 KB`), `jpeg_demo` (`4 KB`), `xTp` (`2 KB`), `xDisplay` (`8 KB`), `xScreen` (`2 KB`).

---

## 5. Complete BLE GATT ATT Database (`app.bin+0x10C8F4`) & `FE EA` Protocol

Extracted directly from the BTstack ATT table inside `app.bin`:

| Service UUID | Name | Characteristics (Handle · Permissions · UUID) |
| :--- | :--- | :--- |
| **`0x1800`** | Generic Access | `0x2A00` Device Name (`R/W`, `h=0x0003`) |
| **`0x1801`** | Generic Attribute | `0x2A05` Service Changed (`I`, `h=0x0006`, CCCD `0x0007`) |
| **`0x180D`** | **Standard Heart Rate** | **`0x2A37` HR Measurement (`N`, `h=0x000A`, CCCD `0x000B`)**, `0x2A38` Sensor Loc (`R`, `h=0x000D`) |
| **`0x180F`** | **Standard Battery** | **`0x2A19` Battery Level (`R/N`, `h=0x0010`, CCCD `0x0011`)** |
| **`0x180A`** | Device Information | `0x2A25` Serial, `0x2A26` FW Rev, `0x2A28` SW Rev, `0x2A29` Manufacturer |
| **`0xFEEA`** | **MoYoung / CRREPA** | `0xFEE1` (`R/N`, `h=0x001D`, CCCD `0x001E`), **`0xFEE2` (`WNR` TX cmd, `h=0x0020`)**, `0xFEE3` (`N` bulk, `h=0x0022`, CCCD `0x0023`), `0xFEE4` (`R`, `h=0x0025`), **`0xFEE5` (`WNR` bulk/OTA/EPO, `h=0x0027`)**, `0xFEE6` (`WNR`, `h=0x0029`) |
| **`0xFEE7`** | **WeChat Sports** | `0xFEC9` MAC (`R`, `h=0x002C`), **`0xFEA1` Live Steps (`R/N`, `h=0x002E`, CCCD `0x002F`)** |

> **Direct PC/Fitness Integration:** Because Watch 4S implements standard Bluetooth SIG **`0x180D` (`0x2A37`)**, **`0x180F` (`0x2A19`)**, and **`0xFEE7` (`0xFEA1`)**, any BLE client (Python `bleak`, Zwift, bike computer) can stream live Heart Rate, Battery %, and Steps without Haylou Fun.

### MoYoung / CRREPA `FE EA` Packet Framing (TX on `0xFEE2`, RX on `0xFEE1`/`0xFEE3`)
Verified in `Lcom/crrepa/f/c2;->a(I[B)[B`:
```text
Byte 0:  0xFE
Byte 1:  0xEA
Byte 2:  0x10 (if MTU == 20)  OR  0x20 + (total_len >> 8)
Byte 3:  total_len & 0xFF   (= len(payload) + 5)
Byte 4:  cmd_id             (command opcode)
Byte 5+: payload bytes      (referenced in firmware as pData[5..])
```

Selected verified BLE command IDs (from `com.crrepa.f.*` & `app.bin`):

| `cmd_id` | Direction / Function |
| :--- | :--- |
| `0x42` / `0x43` / `0xB5` | Future Weather / Today Weather / Extended Today Weather (`city`, `weatherId`, `temp`, `low`, `high`) |
| `0x47` | Push Custom Notification Message (`CRPCustomMessageInfo`) |
| `0x52` | Find Device (`find.*` alarm tone) |
| `0x59` / `0x5C` / `0x5D` | Query 30-Min Hardware Step / Calorie / Exercise Histograms |
| `0x71` / `0x72` / `0x73` | DND Window (`0x71`), Raise-to-Wake Window (`0x72`), Sedentary Reminder (`0x73`) |
| `0x7B` | Music Control state (`0x7B`) |
| `0x87` | High/Low Heart Rate Alert & Drink Water / Handwash reminders |
| `0xB0` / `0xB5` | SOS Emergency Dialer config (`CRPSosInfo`) & Photo Watchface Layout |
| `0xB3` | GNSS Reference Location & EPO A-GPS control |
| `0xB4` | JieLi Watchface Layout & Cloud Dial control |
| `0xB9` | Alarms, **E-Cards / QR Business Cards (`AppAddPostcard`)**, **Calendar Events (`g_curCalendarCount`)**, Daily Goals |
| `0xBB` | **World Clock (`CRPWorldClockInfo`)**, Prayer/Muslim settings, Local Navigation |
| `0xBC` | **GoMore** & Daytime Nap / Sleep Sync |
| `0xFD` / `0xFA` | Auth / Vendor Control framing (`Lcom/crrepa/f/g;`) |

---

## 6. Ground-Truth Capability Matrix & Code Reference Offsets

### Confirmed Present in Watch 4S Firmware
- **Standard BLE HR (`0x180D`) & WeChat Live Steps (`0xFEE7`)**
- **Full Classic BT + BLE HID Remote (`JL_HID` / `edr_hid`):** `KEY_HID_TAKE_PICTURE`, `KEY_HID_CONTROL`, `[hid] send vol inc/dec`, `KEY_MUSIC_PP/PREV/NEXT`, `KEY_OPEN_SIRI`
- **On-Watch GoMore Biometrics SDK:** `healthIndexInitUser`, `VO2 Max`, `Aerobic / Anaerobic`, `24-Hour Sleep`, `Stress`
- **Extra On-Watch Apps & Audio Tones (`mnt/sdfile/res/tone/`):**
  - E-Cards / QR Business Cards (`AppAddPostcard`), World Clock, Calendar, SOS Emergency Dialer, Games (`Restart the Game?`), Calculator, AI Voice / Siri, Flashlight
  - Tones: `drainage.*` (water-eject speaker tone), `wooden_fish.*`, `beads.*`, `Azan_Alarm.*`, `muslim1/2/3.*`, `find.*`, `alarm.*`, `ring.*`
- **Factory / Engineering Test Mode:** `AppFactoryTestHandler` & `AppSetFactoryTestState` (`Function Test`, `Mic Testing`, `Speaker Testing`, `Aging`, `VC30F` LED/PS calibration, `Touch Cross`, `Button`, `Charge`, `SpO2`, `GNSS Test`)
- **Custom Boot Logo / DIY Config Hooks:** `AppGetDiyLogoInfo`, `DiyReadBandInfo` (`MAGIC CODE = MOYOUNG-DIY`)

### Confirmed Absent in Watch 4S Firmware (Zero Code / Strings)
- Native HRV, Blood Pressure, Skin Temperature, ECG, Compass / Magnetometer, NFC / Access Card, Stock Ticker, Quick SMS Replies, True Always-On Display (AOD).

### Key `app.bin` `pi32v2` Code Xref Entry Points (for Future Disassembly)

| Symbol / Handler | String Offset (`app.bin`) | Code Xref (`app.bin`) | XIP VA (`+0x06000120`) |
| :--- | :--- | :--- | :--- |
| `prvAttReadHandler` (`0xFEEA` GATT Server) | `0x0A3EF1` | `0x009DBE` | `0x06009EDE` |
| `AppGetDiyLogoInfo` (Custom Boot Logo) | `0x0A4393` | `0x00F968` | `0x0600FA88` |
| `AppGoToView` (Screen View Switcher) | `0x0A4735` | `0x017B72` | `0x06017C92` |
| `AppStartHealthMeasure` (HR/SpO2/Stress) | `0x0A47C0` | `0x017E18` | `0x06017F38` |
| `KEY_HID_TAKE_PICTURE` (HID Shutter) | `0x0D4870` | `0x01DA00` | `0x0601DB20` |
| `moy_gomore_init` (GoMore SDK Init) | `0x0D4D00` | `0x032ED6` | `0x06032FF6` |
| `AppFactoryTestHandler` (Factory Cmds) | `0x0D2750` | `0x043F50` | `0x06044070` |
| `AppSetFactoryTestState` (`pData[5]`) | `0x0D2771` | `0x0442C0` | `0x060443E0` |
| `prvLSSosBtnTimeEvtHandler` (SOS Button) | `0x0A46E6` | `0x04AD78` | `0x0604AE98` |
| `AppGetFactoryGuideState` | `0x0A4891` | `0x0533E2` | `0x06053502` |
| `AppGetBtSiriState` | `0x0D2973` | `0x06C91A` | `0x0606CA3A` |
| `CheckGomoreKey` | `0x0A4B99` | `0x166D3C` | `0x06166E5C` |
| GATT ATT Database Table | `0x10C8F4` | — | `0x0610CA14` |
| RTOS Task Table (40 tasks) | `0x0D75F8` | — | `0x060D7718` |
| External Flash Partition Table | `0x131064` | — | `0x06131184` |
| Device Identity / Battery LUT / GoMore Defaults | `0x186245` | — | `0x00109251` (SRAM) |
