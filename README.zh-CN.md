# pig-vless

给 [pig](https://github.com/owner888/pig) 编程智能体用的极简 [VLESS](https://xtls.github.io/development/protocols/vless.html) 入站扩展，让跑 Shadowrocket、v2rayNG 或 sing-box 的手机通过 pig 所在的这台机器上网。

[English](README.md)

## 安装

```bash
pig install git:github.com/owner888/pig-vless
```

没有 Composer 依赖。`pig-vless` 原先随 pig 自带，现在是独立包。`pig update` 会删掉旧的自带副本并打印上面这行安装命令；已有的 `vless.*` 设置和 `disabledExtensions: ["pig-vless"]` 继续有效。

## 用法

加载扩展时会把 `vless.listen`（`0.0.0.0:10086`）和自动生成的 `vless.uuid` 写进 `~/.pig/agent/settings.json`，保证手机里的链接重启后依然有效，但**不开口绝不监听端口**：

```text
/vless start      # 开启监听
/vless status     # 查看配置、连接数，以及给手机扫码/复制的 vless:// 链接
/vless stop       # 关闭监听（会话结束时也会自动关闭）
/vless restart
```

## 传输模式与设置

在 `~/.pig/agent/settings.json` 的 `"vless"` 下配置：

| 设置项 | 默认值 | 说明 |
| --- | --- | --- |
| `vless.listen` | `"0.0.0.0:10086"` | `/vless start` 时绑定的监听地址与端口 |
| `vless.uuid` | 自动生成 UUIDv4 | 客户端认证 UUID |
| `vless.cert` | `null` | 证书链 PEM 路径；与 `vless.key` 同时设置时开启非阻塞 TLS |
| `vless.key` | `null` | 私钥 PEM 路径 |
| `vless.wsPath` | `null` | 设置后（如 `"/vless"`）启用 VLESS over WebSocket（`type=ws&path=%2Fvless`，RFC 6455 二进制帧 + `Sec-WebSocket-Protocol` 0-RTT Early Data）；不设置则为原生 TCP |

目标域名通过 `Pig\Async\Dns` 在事件循环外异步解析，不阻塞主循环。

## 开发

测试对着一份 pig 检出运行：

```bash
PIG_DIR=~/path/to/pig ~/path/to/pig/vendor/bin/phpunit -c phpunit.xml
```

`PIG_DIR` 默认是本包旁边的 `pig` 目录。

## 许可

MIT，见 [LICENSE](LICENSE)。
