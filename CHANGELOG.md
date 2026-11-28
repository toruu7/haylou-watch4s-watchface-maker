# Changelog

## 2.0.0

### Pure-Python Haylou Fun APK Patcher & Health/BLE Suite
- Replaced external Java/`zipalign`/`apksigner` requirements with zero-dependency pure-Python `scripts/dex_patcher_lib.py` and `scripts/apk_signer.py` (4-byte/4KB alignment + APK Signature Scheme v2 & v3 signing).
- Added modular CLI flags to `scripts/patch_and_build_apk.py`:
  - `--unlock-cards`: Unlocks PAI/Vitality, VO2 Max, HRV, Active/Standing Hours, High/Low HR Alert (`0x87 02`), and Daytime Sleep Naps (`0xBC 01`), while keeping unsupported Quick Reply getters at stock.
  - `--rhr`: Adds a 3rd Resting Heart Rate card to Heart Rate Details (Day, Week, Month & Year tabs).
  - `--vitality-vo2`: On-device Vitality Score (PAI) and VO2 Max engines (30-day backfill + live sync).
  - `--workout-analytics`: Aerobic/Anaerobic Training Effect (`0.2–5.0`), Exercise Load (EPOC), Recovery Time, per-workout VO2 Max, missing workout Avg/Max/Min HR stats from `heartrate[]`, and 10-second moving GPS cycling speed streams (`SportTable.speedArray` / `SportNetBean.speedList`) unlocking Haylou Fun's Speed Line Chart & Fastest Speed.
  - Health Connect Sleep sync fix (`patch_classes6_hc_sleep_fix`): guards `HealthConnectManager$insertSleep$1` against Watch 4S zero-duration sleep stages (`startTime must be before endTime`).
  - `--hrv-active`: Stress-derived 30-min HRV (`HrvTable`) and Hourly Active/Standing Hours (`StepDataTable.activeItems[24]`).
  - `--hourly-charts`: Unlocks Watch 4S BLE `0x59` 30-min hardware step histograms and Hourly Steps/Calories/Exercise Day (`D`) tabs.
  - `--night-raise-to-wake`: Wires Device Settings → DND schedule exclusively to BLE `0x72` Raise-to-Wake (`23:00–07:00` default off) while keeping calls & notifications active.
  - `--cycling-fixes`: Strips phantom handlebar-vibration steps via exact `0x59` overlap, computes true moving time/speed (keeping GPS points intact for Strava), and adds live GPS auto-pause/auto-resume.
  - `--voip-calls`: VoIP incoming call alerts with caller name (`BLE 0x41`) and wrist reject for WhatsApp, Messenger, Instagram, Telegram, Viber, and Discord.
- Fixed `ls25plate.bin` Dalvik size check (`if-lez` `0x3d`) and `01 1a` dummy `DT#0` invariant resolving watchface sync Error Code 3.

### Watch 4S Studio & LS26 `.bin` Compiler
- Full hardware-verified LS26 opcode suite (`01 00`–`01 2e`): Z-order layer stack, Tap-to-Switch (`01 1a`), procedural bezels, multi-zone animated GIF/WebP (`01 2e`), 9-state Weather (`01 1b`) + Temperature (`01 1c`), Bluetooth badge (`01 14`), live Seconds (`01 18`), AM/PM (`01 11`), multi-gauge stacking (`01 12`) + native battery bar (`01 05`), and custom PNG stickers & hands.
- Added built-in **Alien Force · 5 Holograms** template with unified `<50%` auto-red Omnitrix + color-matched battery ring (`01 12 sub=0x06`), 5 tap-switch holograms, and **Omnitrix Silver Glass** hands.
- Added RLE blob deduplication, `960 KB` flash-budget validation, exclusive Windows port binding (`SO_EXCLUSIVEADDRUSE`), and ADB cold-start timeout fixes.
- Refreshed README, screenshots, and full technical documentation (`docs/apk_patcher_guide.md`, `docs/hardware_architecture.md`, `docs/haylou_watch4s_customizer_guide.md`).

## 1.1.0

- Studio: added an inline, dismissible first-run guide and a reusable `?` help button.
- Studio: added single-file `.face.zip` export/import for sharing dials.
- Studio: preview renders are now sequenced — older responses cannot overwrite newer ones.
- Studio: drag positioning handles cancelled pointers, lost capture and window blur.
- Studio: arrow keys nudge the selected layer (hold Shift for 1px steps).
- Studio: long names and subtitles are truncated/clamped so the gallery grid stays intact.
- Studio: gallery, export, import and error states now use consistent JSON error messages.
- Backend: preset ids are containment-checked; uploads have size/format validation; cross-origin and foreign-Host requests are rejected.
- Backend: system font discovery now works on Windows, macOS and Linux.
- Backend: ADB status reports whether the patched Haylou Fun is installed.
- Packaging: pinned Pillow, added `pyproject.toml`, `launch_studio.sh`, CI and contributor docs.

## 1.0.0

- Initial public release of the visual Studio, `.bin` compiler, preset library and APK patcher.
