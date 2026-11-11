# pig-vless — notes for agents

VLESS inbound for pig, as a pig package. `README.md` says what it does; this says how it is
worked on. Keep this file under 100 lines.

## Shape

- `src/VlessServer.php` runs the listener, non-blocking TLS handshake, VLESS header parser,
  `Pig\Async\Dns` lookup and dual-`TcpConnection` relay.
- `src/Raw.php` is the unframed TCP protocol; `src/WsBinary.php` is the RFC 6455 binary
  WebSocket protocol (with `Sec-WebSocket-Protocol` 0-RTT early data).
- `extensions/pig-vless.php` registers the autoloader, the session hooks and `/vless`.

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
