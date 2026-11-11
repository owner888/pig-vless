# Changelog

What changed, newest first, in pig's format: `## Unreleased` while working, `## [x.y.z] - YYYY-MM-DD`
at release. The version lives in the git tag only.

## [0.1.0] - 2026-11-11

### New Features

- **A package of its own** — `pig-vless` is no longer bundled with pig: `pig install git:github.com/owner888/pig-vless`. Same `/vless start | stop | restart | status` command and `vless.*` settings; `disabledExtensions: ["pig-vless"]` carries over. `pig update` removes the old bundled copy.
- **VLESS over WebSocket (`vless.wsPath`)** — RFC 6455 binary frames (`OPCODE_BINARY`), `Sec-WebSocket-Protocol` 0-RTT early data, and `type=ws&path=…` share links alongside raw TCP and TLS.
- **Non-blocking DNS resolution** — domain targets are resolved off the event loop through `Pig\Async\Dns` while buffering early payload bytes.
