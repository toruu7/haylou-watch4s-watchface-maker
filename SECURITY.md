# Security policy

The Studio is a local-only tool. It binds to `127.0.0.1`, never opens a network port to
LAN/WAN, and sends no telemetry.

## Reporting a vulnerability

Please open a private security advisory on GitHub rather than a public issue. Include
the endpoint or component affected, a reproduction, and the impact. We will acknowledge
within a few days and coordinate a fix before disclosure.

## What is intentionally local

- The HTTP API rejects foreign `Host` and `Origin` headers.
- Preset ids are canonical-path checked; absolute paths and traversal are rejected.
- Uploads are size-limited and validated (font magic bytes, `.bin` header flags).
- The ADB install endpoint is confirmation-gated in the UI.

## What you must handle yourself

- Install only APKs you patched from your own legally obtained Haylou Fun copy.
- Keep your `keystore/` private. It is gitignored for a reason.
- ADB access grants your PC full control of the phone. Only connect devices you trust.
