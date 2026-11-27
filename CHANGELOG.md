# Changelog

What changed, newest first, in pig's format: `## Unreleased` while working, `## [x.y.z] - YYYY-MM-DD`
at release. The version lives in the git tag only.

## [0.2.0] - 2026-11-25

### New Features

- **VLESS + TCP + REALITY (`src/Reality.php`)** — Pure-PHP TLS 1.3 + REALITY record-layer protocol over `ext-openssl`: X25519 ECDH (`0x001d` and hybrid `X25519MLKEM768` `0x11ec`), HKDF-SHA256 (`"REALITY"`) + AES-256-GCM authentication of `ClientHello.sessionId`, temporary Ed25519 X.509 certificate signed with `HMAC-SHA512(AuthKey, ed25519Pub)`, transparent fallback to `dest` on unauthorized probes, `/vless keygen` command, and `security=reality&flow=xtls-rprx-vision&pbk=…&sid=…` share links.
- **XTLS Vision (`src/Vision.php`, `flow=xtls-rprx-vision`)** — VLESS protobuf `Addons.Flow` decoding, randomized inner TLS handshake padding/unpadding, inner TLS 1.3 detection, and zero-copy direct splice (`CommandPaddingDirect = 2`, bypassing outer TLS 1.3 AEAD once inner `ApplicationData` starts).

## [0.1.0] - 2026-11-11

### New Features

- **A package of its own** — `pig-vless` is no longer bundled with pig: `pig install git:github.com/owner888/pig-vless`. Same `/vless start | stop | restart | status` command and `vless.*` settings; `disabledExtensions: ["pig-vless"]` carries over. `pig update` removes the old bundled copy.
- **VLESS over WebSocket (`vless.wsPath`)** — RFC 6455 binary frames (`OPCODE_BINARY`), `Sec-WebSocket-Protocol` 0-RTT early data, and `type=ws&path=…` share links alongside raw TCP and TLS.
- **Non-blocking DNS resolution** — domain targets are resolved off the event loop through `Pig\Async\Dns` while buffering early payload bytes.
