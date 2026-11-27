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
/vless keygen     # generate an X25519 key pair + shortId and enable REALITY + XTLS Vision
```

## Transports & Settings

Configure under `"vless"` in `~/.pig/agent/settings.json`:

| Setting | Default | Description |
| --- | --- | --- |
| `vless.listen` | `"0.0.0.0:10086"` | Address and port to bind when `/vless start` is run |
| `vless.uuid` | generated UUIDv4 | Client UUID |
| `vless.reality` | `null` | When set (or generated via `/vless keygen`), enables pure-PHP **VLESS + TCP + REALITY + XTLS Vision (`xtls-rprx-vision`)** with transparent fallback to `dest` and zero-copy splice |
| `vless.cert` | `null` | Path to fullchain PEM certificate; with `vless.key`, enables non-blocking TLS |
| `vless.key` | `null` | Path to private key PEM |
| `vless.wsPath` | `null` | When set (e.g. `"/vless"`), serves VLESS over WebSocket (`type=ws&path=%2Fvless`, RFC 6455 binary frames + `Sec-WebSocket-Protocol` 0-RTT early data) instead of raw TCP |

### REALITY + XTLS Vision (`vless.reality`)

Run `/vless keygen` inside pig to auto-generate an X25519 key pair and `shortId`, or configure `"reality"` under `"vless"`:

```json
{
  "vless": {
    "listen": "0.0.0.0:443",
    "uuid": "7a3f1c2e-9b4d-4e6f-8a1b-2c3d4e5f6a7b",
    "reality": {
      "privateKey": "…",
      "publicKey": "…",
      "dest": "www.apple.com:443",
      "serverNames": ["www.apple.com"],
      "shortIds": ["a1b2c3d4"],
      "fingerprint": "chrome",
      "flow": "xtls-rprx-vision"
    }
  }
}
```

- **Pure-PHP TLS 1.3 + REALITY**: Authenticates the client's `ClientHello.sessionId` via X25519 ECDH (`0x001d` or hybrid `X25519MLKEM768` `0x11ec`), HKDF-SHA256 (`"REALITY"`), and AES-256-GCM; issues a temporary Ed25519 X.509 certificate signed with `HMAC-SHA512(AuthKey, ed25519Pub)`. Unauthorized probes or browsers are transparently forwarded to `dest`.
- **XTLS Vision (`xtls-rprx-vision`)**: Pads and unpads inner TLS handshakes, detects inner TLS 1.3 traffic, and switches both uplink and downlink to zero-copy direct splice (`CommandPaddingDirect = 2`) once inner `ApplicationData` begins.

Target domain names are resolved off the event loop through `Pig\Async\Dns`.

## Development

The tests run against a pig checkout:

```bash
PIG_DIR=~/path/to/pig ~/path/to/pig/vendor/bin/phpunit -c phpunit.xml
```

`PIG_DIR` defaults to a `pig` directory next to this package.

## License

MIT — see [LICENSE](LICENSE).
