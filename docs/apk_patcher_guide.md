# Haylou Fun v4.0.8 Pure-Python APK Patcher Guide

`scripts/patch_and_build_apk.py` is a modular, **zero-Java** DEX bytecode patcher and APK signer for **Haylou Fun v4.0.8** tailored specifically to the **Haylou Watch 4S (`LS26`)**.

It uses:
- [`scripts/dex_patcher_lib.py`](../scripts/dex_patcher_lib.py) — pure-Python DEX reader, method inspector, and Dalvik bytecode assembler.
- [`scripts/apk_signer.py`](../scripts/apk_signer.py) — pure-Python 4-byte / 4 KB page alignment and APK Signature Scheme v2 & v3 signing via `cryptography` (auto-generates a local RSA-2048 debug keystore at `keystore/debug.keystore` if none exists).

No JDK, `keytool`, `zipalign`, or Android SDK Build-Tools are required.

---

## Usage

```bash
# Apply all verified Watch 4S patches (default):
python scripts/patch_and_build_apk.py --src /path/to/haylou-fun-v4-0-8.apk --all

# Custom Night Raise-to-Wake off window (default: 23:00-07:00):
python scripts/patch_and_build_apk.py --src /path/to/haylou-fun-v4-0-8.apk --all --night-hours 22:30-06:30

# Apply only selected modules:
python scripts/patch_and_build_apk.py --src /path/to/haylou-fun-v4-0-8.apk --noclock --unlock-cards --rhr --voip-calls

# Capture mode (saves downloaded cloud .bin files to external cache instead of sideloading):
python scripts/patch_and_build_apk.py --src /path/to/haylou-fun-v4-0-8.apk --noclock --mode capture
```

### Output Files
- `--all` (or health patches): `haylou-fun-v4-0-8-full-health.apk`
- `--noclock` only: `haylou-fun-v4-0-8-noclock.apk`
- Custom output path: pass `--out /path/to/custom.apk`

---

## Modular Patch Reference

### 1. `--noclock` (Watchface Sideloading + FB Signature Bypass)
- **`classes.dex`**: Patches `Lcom/crrepa/f/a2;->a(CRPWatchFaceLayoutInfo;)[B` so photo-dial layout command `0xB0` suppresses default clock digits and widgets.
- **`classes3.dex`**: Overrides `FacebookSdk.getApplicationSignature(Context)` to return Haylou's release key hash (`UHVvEzDXInBYrb0oGpukqdW1VV4=`) so Facebook login works on debug-signed builds.
- **`classes6.dex`**: Redirects `ls25plate.bin` to `Context.getExternalCacheDir()` (`/sdcard/Android/data/com.yingsheng.hayloufun/cache/ls25plate.bin`) with proper `if-lez` file-size validation so Watch 4S Studio dials stream directly through Dial Center.

### 2. `--unlock-cards` (Hidden WatchConfig Features)
Patches `Lcom/yingsheng/protocol/config/WatchConfig;` getters in `classes7.dex` to return `true` for hardware-verified Watch 4S features:
- `isSupportPai()` — Vitality Score / PAI
- `isSupportVo2Max()` — VO2 Max
- `isSupportHrv()` — Heart Rate Variability
- `isSupportActiveByHour()` — Active / Standing Hours
- `isSupportHeartWarning()` — High/Low Heart Rate Alert (`BLE 0x87 02`)
- `isSupportSleepNap()` — Daytime Sleep Naps (`BLE 0xBC 01`)

> Note: `isSupportQuickReplyMsg` and `isSupportWhatsAppQuickReplyMsg` are intentionally kept at stock behavior because Watch 4S (`LS26`) firmware silently ignores Quick Reply BLE commands (`0xB9 0x19` / `0xBB 0x21`).

### 3. `--rhr` (Resting Heart Rate Card)
Adds a 3rd **Resting Heart Rate** card alongside Heart Rate Range and Average Heart Rate in Heart Rate Details (`Day`, `Week`, `Month`, and `Year` tabs), computed cleanly from the lowest sustained quiet HR window without breaking Compose recomposition state.

### 4. `--vitality-vo2` (Vitality Score / PAI + VO2 Max Engine)
Adds on-device calculation engines in `classes6.dex` that compute daily PAI (Personal Activity Intelligence) and VO2 Max from Watch 4S heart rate records — backfilling up to 30 days on Home launch and updating live on every BLE HR sync.

### 5. `--workout-analytics` (Training Effect, EPOC, HR Stats & Cycling Speed Chart)
Computes the workout metrics Watch 4S leaves blank in `SportDetailActivity` (runs live before Haylou Cloud upload + 30-day backfill on Home launch):
- **HR Summary Stats**: Populates missing `SportTable.avrHeartRate`, `maxHeartRate`, and `minHeartRate` directly from the workout's `heartrate[]` samples (45–225 bpm).
- **Cycling GPS Speed Stream (`speedArray` / `speedList`)**: Computes smoothed 10-second moving GPS speed samples in native `(int)(km/h * 100)` units (spike-rejected `> 90 km/h`, skipping `> 30s` stop gaps) from `SportTable.points`, unlocking Haylou Fun's native **Speed Line Chart** & **Fastest Speed** metric and supplying `speedList` to Haylou Cloud.
- **Training Analytics**: Computes **Aerobic & Anaerobic Training Effect (`0.2–5.0`)**, **Exercise Load / EPOC**, **Recovery Time (minutes)**, and **Per-Workout VO2 Max**.

### 5b. Health Connect Sleep Zero-Duration Stage Fix *(always applied on `classes6.dex`)*
Patches `HealthConnectManager$insertSleep$1.invokeSuspend` in-place to skip zero-duration or clamped-overflow sleep stages (`stageEnd <= stageStart`) before constructing `SleepSessionRecord$Stage`, preventing `IllegalArgumentException: startTime must be before endTime` when Watch 4S emits a 0-minute stage.

### 6. `--hrv-active` (Stress-Derived HRV & Standing Hours)
- **HRV Engine**: Derives 30-minute HRV values (`HrvTable`) from Watch 4S's 24/7 PPG Stress and quiet HR readings.
- **Active Hours Engine**: Populates `StepDataTable.activeItems[24]` for the 12-hour Active / Standing Hours tracker (30-day backfill + live refresh).

### 7. `--hourly-charts` (Native BLE `0x59` Step Histograms)
Unlocks Watch 4S's native 30-minute hardware step histograms (`BLE 0x59` `queryStepsCategory`), populates hourly Steps, Calories & Exercise arrays, and unhides the **Day (`D`)** tabs and hourly bar charts across Daily Activities, Steps, Calories, and Home mini cards.

### 8. `--night-raise-to-wake` (Scheduled Wrist-Wake Off at Night)
Unhides **Device Settings → Do Not Disturb mode** and wires it exclusively to Watch 4S's **Raise-to-Wake schedule** (`BLE 0x72` `sendQuickViewTime`). Default window is `23:00–07:00` off (`07:00–23:00` active), keeping incoming calls and notifications enabled overnight while preventing accidental screen wakeups.

### 9. `--cycling-fixes` (Cycling Accuracy & Strava Compatibility)
Three targeted fixes for Watch 4S cycling workouts:
1. **Phantom Step Removal**: Strips handlebar-vibration steps during cycling windows using exact `0x59` 30-minute hardware overlap (persisted across midnight in local-only `SportTable.sportcounter`, with a `30 steps/min` fallback for older days) while preserving bike distance and calories.
2. **True Moving Time & Speed**: Recomputes true moving time and moving average speed across deduplicated `>30s` GPS stops while keeping `SportTable.points` intact so Strava's velocity curve stays smooth.
3. **Live GPS Auto-Pause / Auto-Resume**: Automatically pauses phone-started cycling when speed drops below `3.6 km/h` for 5 seconds and resumes at `>= 5.4 km/h`.

### 10. `--voip-calls` (VoIP Incoming Call Alerts + Wrist Reject)
Intercepts incoming call notifications from **WhatsApp, WhatsApp Business, Messenger, Instagram, Telegram, Viber, and Discord**, rings the Watch 4S with the real caller name over `BLE 0x41`, stops ringing automatically when answered/missed, and triggers the VoIP app's **Decline** action when rejected from the watch.

---

## Installing the Patched APK

### Option A: USB (ADB)
```bash
adb install -r haylou-fun-v4-0-8-full-health.apk
```
*(If upgrading from the Google Play Store release for the first time, Android requires uninstalling the Play Store build first due to the different signing key; log back into your Haylou account afterward to restore cloud-synced data.)*

### Option B: Wireless (Local Wi-Fi / Tailscale)
```bash
python -m http.server 8080 --directory .
```
Open `http://<YOUR_PC_IP>:8080/haylou-fun-v4-0-8-full-health.apk` in your phone's browser and install.

> [!IMPORTANT]
> Disable **Enable auto update** for **Haylou Fun** in the Google Play Store so Play Store does not overwrite your patched build.
