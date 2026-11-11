# pig-vless

A minimal [VLESS](https://xtls.github.io/en/development/protocols/vless.html) inbound for the [pig](https://github.com/owner888/pig) coding agent, so a phone running Shadowrocket, v2rayNG or sing-box can route through the machine pig is on.

[中文](README.zh-CN.md)

## Installation

```bash
pig install git:github.com/owner888/pig-vless
```

No Composer dependencies. `pig-vless` was bundled with pig until it became this package. `pig update` removes the old bundled copy and prints the install line above; your `vless.*` settings and `disabledExtensions: ["pig-vless"]` carry over.

## Usage

Loading the extension writes `vless.listen` (`0.0.0.0:10086`) and a generated `vless.uuid` into `~/.pig/agent/settings.json` so the phone's link stays valid across restarts, but **listens on nothing until you ask**:

```text
/vless start      # open the port
/vless status     # configuration, state, and the vless:// link for the phone
/vless stop       # close it; the session ending does this too
/vless restart
```

## Transports & Settings

Configure under `"vless"` in `~/.pig/agent/settings.json`:

| Setting | Default | Description |
| --- | --- | --- |
| `vless.listen` | `"0.0.0.0:10086"` | Address and port to bind when `/vless start` is run |
| `vless.uuid` | generated UUIDv4 | Client UUID |
| `vless.cert` | `null` | Path to fullchain PEM certificate; with `vless.key`, enables non-blocking TLS |
| `vless.key` | `null` | Path to private key PEM |
| `vless.wsPath` | `null` | When set (e.g. `"/vless"`), serves VLESS over WebSocket (`type=ws&path=%2Fvless`, RFC 6455 binary frames + `Sec-WebSocket-Protocol` 0-RTT early data) instead of raw TCP |

Target domain names are resolved off the event loop through `Pig\Async\Dns`.

## Development

The tests run against a pig checkout:

```bash
PIG_DIR=~/path/to/pig ~/path/to/pig/vendor/bin/phpunit -c phpunit.xml
```

`PIG_DIR` defaults to a `pig` directory next to this package.

## License

MIT — see [LICENSE](LICENSE).
