# Contributing

Thanks for helping improve the Studio. This project is MIT licensed and community-maintained.

## Development setup

```bash
python -m pip install -r requirements.txt
python studio/server.py          # opens http://127.0.0.1:8466
```

Use `launch_studio.bat` (Windows) or `./launch_studio.sh` (macOS/Linux) for a guided start.
Set `STUDIO_PORT=8467` if port 8466 is taken, and `STUDIO_LOG=1` to log requests to stderr.

## Ground rules

- **Never touch the watch firmware.** Dial files go into the official photo-dial slot only.
  Do not add code that flashes bootloaders, partitions, or OTA payloads.
- **Never redistribute Haylou's APK.** Users supply their own official copy. The patched
  APK and keystore are gitignored; keep them that way.
- **Keep the compiler authoritative.** `scripts/watchface_compiler.py` defines the `.bin`
  format. If you add a browser renderer, verify it against the Python output.
- **Preserve the Studio's visual language.** It is an Operate surface: restrained,
  consistent controls, no gratuitous motion. Changes to `studio/index.html` should keep
  the existing macOS-style tokens and component vocabulary.

## Before opening a PR

- `python -m compileall -q scripts studio`
- Run the Studio and check: gallery empty state, save, edit, push (with and without a phone),
  import/export bundle, preview after rapid slider changes.
- If you changed UI, include a screenshot at the default window size.
- Add a CHANGELOG entry under "Unreleased" when the change is user-visible.

## Reporting issues

Include your OS, Python version, `adb devices -l` output, the exact step that failed, and
the error text shown in the Studio toast. Never attach the official APK or your keystore.

## Security

See [SECURITY.md](SECURITY.md). Please report security issues privately rather than in
a public issue.
