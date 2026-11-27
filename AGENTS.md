# pig-vless — notes for agents

VLESS inbound for pig, as a pig package. `README.md` says what it does; this says how it is
worked on. Keep this file under 100 lines.

## Shape

- `src/VlessServer.php` runs the listener, non-blocking TLS or REALITY handshake, VLESS header
  (+ protobuf `Addons.Flow`) parser, `Pig\Async\Dns` lookup and dual-`TcpConnection` relay.
- `src/Reality.php` implements the pure-PHP TLS 1.3 + REALITY record-layer protocol (`ext-openssl`
  X25519 ECDH, HKDF-SHA256/384, AES-GCM/ChaCha20-Poly1305, HMAC-SHA512 temporary Ed25519 X.509
  certificate, transparent fallback to `dest`, and zero-copy splice switches).
- `src/Vision.php` implements XTLS Vision (`xtls-rprx-vision`) padding/unpadding, inner TLS 1.3
  detection, and `CMD_DIRECT` zero-copy splice transition.
- `src/Raw.php` is the unframed TCP protocol; `src/WsBinary.php` is the RFC 6455 binary
  WebSocket protocol (with `Sec-WebSocket-Protocol` 0-RTT early data).
- `extensions/pig-vless.php` registers the autoloader, the session hooks and `/vless` (`start | stop | restart | status | keygen`).

## Rules

- `declare(strict_types=1)`, PSR-12, one class per file, no `@` suppression, no silent fallback.
- The developer's name does not appear in this repository; write "the developer".
- No composer dependencies. The entry file keeps its name (`pig-vless.php`) so
  `disabledExtensions: ["pig-vless"]` carries over.
- Git (commit, tag, push) is the developer's; report which files changed.

## Tests

`PIG_DIR=~/path/to/pig ~/path/to/pig/vendor/bin/phpunit -c phpunit.xml`

## Changelog

`CHANGELOG.md` in pig's format: `## Unreleased` while working, `## [x.y.z] - YYYY-MM-DD` at
release; the version lives in the git tag only.
