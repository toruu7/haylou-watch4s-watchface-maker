# Changelog

## Unreleased

- No changes yet.

## 1.1.0

- Studio: added an inline, dismissible first-run guide and a reusable `?` help button.
- Studio: added single-file `.face.zip` export/import for sharing dials.
- Studio: preview renders are now sequenced — older responses cannot overwrite newer ones.
- Studio: drag positioning handles cancelled pointers, lost capture and window blur.
- Studio: arrow keys nudge the selected layer (hold Shift for 1px steps).
- Studio: long names and subtitles are truncated/clamped so the gallery grid stays intact.
- Studio: gallery, export, import and error states now use consistent JSON error messages.
- Backend: preset ids are containment-checked; uploads have size/format validation;
  cross-origin and foreign-Host requests are rejected.
- Backend: system font discovery now works on Windows, macOS and Linux.
- Backend: ADB status reports whether the patched Haylou Fun is installed.
- Packaging: pinned Pillow, added `pyproject.toml`, `launch_studio.sh`, CI and contributor docs.

## 1.0.0

- Initial public release of the visual Studio, `.bin` compiler, preset library and APK patcher.
