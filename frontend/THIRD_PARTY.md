# Local QR dependencies

- `qrcode-generator.js`: existing Kazuhiko Arase QR encoder; MIT license in its source header. Encoding and high error correction are reused by `qr-renderer.js`.
- `jsqr.js`: jsQR **1.4.0**, the same dependency/version already referenced by the scanner. This local copy verifies customized generator images without a CDN request. Apache-2.0 license: `LICENSE-jsQR.txt`.
  - Source: https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js
  - License: https://cdn.jsdelivr.net/npm/jsqr@1.4.0/LICENSE
  - SHA-256: `bc40c8a15196236b2314db0856f72ca0b49980cd5413b8c852a7349f5fee0859`

No new encoder, styling framework, build step or remote QR generation service is used. The scanner's existing camera dependency remains unchanged.
