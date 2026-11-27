<?php

declare(strict_types=1);

namespace PigVless;

use Pig\Async\Async;
use Pig\Async\Dns;
use Pig\Async\Loop;
use Pig\CodingAgent\Logger;
use Pig\CodingAgent\Web\Connection;
use Pig\CodingAgent\Web\Protocols\Http;
use Pig\CodingAgent\Web\TcpConnection;

/**
 * A VLESS inbound, the smallest one that a phone can use: TCP or WebSocket, one UUID, REALITY +
 * XTLS Vision (`xtls-rprx-vision`), TLS if a certificate is configured, or plain.
 *
 * VLESS is the thinnest of the V2Ray protocols — a header and then bytes:
 *
 *     request:  version(1)=0 | uuid(16) | addons-len(1) addons | command(1) | port(2, BE)
 *               | address-type(1) address | payload…
 *     response: version(1)=0 | addons-len(1)=0 | payload…
 *
 * Commands are 1 TCP, 2 UDP, 3 MUX; address types 1 IPv4 (4 bytes), 2 domain (len + name),
 * 3 IPv6 (16 bytes). This serves TCP and closes on the other two: UDP over a stream needs
 * per-packet framing on both ends, and MUX a whole multiplexer, and neither is "a phone
 * through the Mac". Shadowrocket falls back to direct for UDP when the proxy declines it.
 *
 * The relay is two `TcpConnection`s — over `Reality` (pure-PHP TLS 1.3 + REALITY authentication
 * with transparent dest fallback and XTLS Vision zero-copy splice), `Raw` for plain TCP/TLS, or
 * `WsBinary` (RFC 6455 binary frames after an HTTP upgrade on `$wsPath`, with
 * `Sec-WebSocket-Protocol` 0-RTT early data) for WebSocket — one for the phone, one for where it
 * asked to go, each writing what the other reads. Domain names are resolved off the loop through
 * `Pig\Async\Dns`, and the outbound connect is asynchronous (`STREAM_CLIENT_ASYNC_CONNECT`, then
 * one writable wakeup).
 */
final class VlessServer
{
    public const int CMD_TCP = 1;

    public const int CMD_UDP = 2;

    public const int CMD_MUX = 3;

    /** @var resource|null */
    private $socket = null;

    private ?string $watcher = null;

    /** @var array<int, Connection> every live socket, phone and far end alike */
    private array $connections = [];

    private int $nextId = 0;

    /** @var array<int, string> the pending TLS handshakes' watchers */
    private array $handshakes = [];

    /** @var string the uuid as its 16 bytes */
    private readonly string $uuid;

    /** WebSocket upgrade path (e.g. `/vless`), or null for raw TCP. */
    public readonly ?string $wsPath;

    /**
     * Normalized REALITY settings when enabled, or null.
     *
     * @var array{
     *     privateKeyRaw: string,
     *     publicKey: string,
     *     destHost: string,
     *     destPort: int,
     *     serverNames: list<string>,
     *     shortIds: list<string>,
     *     primaryShortIdHex: string,
     *     fingerprint: string,
     *     flow: string,
     *     maxTimeDiff: int
     * }|null
     */
    public readonly ?array $reality;

    /**
     * @param string                    $uuid    as written, with or without dashes
     * @param string|null               $cert    PEM path; with `$key` turns the listener into TLS
     * @param string|null               $key     PEM path
     * @param string|null               $wsPath  when set, expects a WebSocket upgrade at this path (`type=ws`)
     * @param array<string, mixed>|null $reality when set (with `privateKey`), enables REALITY + XTLS Vision
     */
    public function __construct(
        public readonly string $host,
        public readonly int $port,
        string $uuid,
        public readonly ?string $cert = null,
        public readonly ?string $key = null,
        ?string $wsPath = null,
        ?array $reality = null,
    ) {
        $hex = str_replace('-', '', $uuid);

        if (strlen($hex) !== 32 || !ctype_xdigit($hex)) {
            throw new \InvalidArgumentException("Not a UUID: {$uuid}");
        }

        $this->uuid = hex2bin($hex);
        $trimmedPath = $wsPath !== null ? trim($wsPath) : '';
        $this->wsPath = $trimmedPath !== '' ? '/' . ltrim($trimmedPath, '/') : null;
        $this->reality = self::normalizeReality($reality);
    }

    /**
     * @param array<string, mixed>|null $cfg
     * @return array{
     *     privateKeyRaw: string,
     *     publicKey: string,
     *     destHost: string,
     *     destPort: int,
     *     serverNames: list<string>,
     *     shortIds: list<string>,
     *     primaryShortIdHex: string,
     *     fingerprint: string,
     *     flow: string,
     *     maxTimeDiff: int
     * }|null
     */
    private static function normalizeReality(?array $cfg): ?array
    {
        if ($cfg === null || !is_string($cfg['privateKey'] ?? null) || trim($cfg['privateKey']) === '') {
            return null;
        }
        $privRaw = Reality::decodeKey($cfg['privateKey']);
        $pubRaw = is_string($cfg['publicKey'] ?? null) && trim($cfg['publicKey']) !== ''
            ? Reality::decodeKey($cfg['publicKey'])
            : Reality::publicKeyFromPrivate($privRaw);
        $pubEncoded = Reality::base64UrlEncode($pubRaw);

        $dest = is_string($cfg['dest'] ?? null) && trim($cfg['dest']) !== '' ? trim($cfg['dest']) : 'www.apple.com:443';
        if (str_contains($dest, ':')) {
            [$destHost, $destPortStr] = explode(':', $dest, 2);
            $destPort = ctype_digit($destPortStr) ? (int) $destPortStr : 443;
        } else {
            $destHost = $dest;
            $destPort = 443;
        }

        $serverNames = [];
        $rawSnis = $cfg['serverNames'] ?? (isset($cfg['serverName']) ? [$cfg['serverName']] : [$destHost]);
        if (is_array($rawSnis)) {
            foreach ($rawSnis as $s) {
                if (is_string($s) && trim($s) !== '') {
                    $serverNames[] = strtolower(trim($s));
                }
            }
        }

        $shortIds = [];
        $primaryShortIdHex = '';
        $rawSids = $cfg['shortIds'] ?? (isset($cfg['shortId']) ? [$cfg['shortId']] : ['']);
        if (is_array($rawSids)) {
            foreach ($rawSids as $sid) {
                if (is_string($sid)) {
                    $shortIds[] = Reality::decodeShortId($sid);
                    if ($primaryShortIdHex === '' && trim($sid) !== '') {
                        $primaryShortIdHex = strtolower(trim($sid));
                    }
                }
            }
        }
        if ($shortIds === []) {
            $shortIds[] = str_repeat("\x00", 8);
        }

        $fp = is_string($cfg['fingerprint'] ?? null) && trim($cfg['fingerprint']) !== ''
            ? trim($cfg['fingerprint'])
            : 'chrome';
        $flow = is_string($cfg['flow'] ?? null) ? trim($cfg['flow']) : Vision::FLOW;
        $maxTimeDiff = is_int($cfg['maxTimeDiff'] ?? null) ? max(0, $cfg['maxTimeDiff']) : 0;

        return [
            'privateKeyRaw' => $privRaw,
            'publicKey' => $pubEncoded,
            'destHost' => $destHost,
            'destPort' => $destPort,
            'serverNames' => $serverNames,
            'shortIds' => $shortIds,
            'primaryShortIdHex' => $primaryShortIdHex,
            'fingerprint' => $fp,
            'flow' => $flow,
            'maxTimeDiff' => $maxTimeDiff,
        ];
    }

    public function isReality(): bool
    {
        return $this->reality !== null;
    }

    public function isTls(): bool
    {
        return !$this->isReality() && $this->cert !== null && $this->key !== null;
    }

    public function isWs(): bool
    {
        return !$this->isReality() && $this->wsPath !== null;
    }

    /** @throws \RuntimeException when the port cannot be bound or the certificate cannot be read */
    public function start(): void
    {
        if ($this->isTls()) {
            foreach ([$this->cert, $this->key] as $file) {
                if (!is_readable((string) $file)) {
                    throw new \RuntimeException("Cannot read {$file}");
                }
            }
        }

        $address = "tcp://{$this->host}:{$this->port}";
        $errno = 0;
        $errstr = '';

        set_error_handler(static fn () => true);

        try {
            $socket = stream_socket_server($address, $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $this->context());
        } finally {
            restore_error_handler();
        }

        if ($socket === false) {
            throw new \RuntimeException("Could not bind VLESS to {$address}: {$errstr} ({$errno})");
        }

        stream_set_blocking($socket, false);
        $this->socket = $socket;
        $this->watcher = Loop::get()->onReadable($socket, function (): void {
            set_error_handler(static fn () => true);

            try {
                $client = stream_socket_accept($this->socket, 0);
            } finally {
                restore_error_handler();
            }

            if ($client !== false) {
                stream_set_blocking($client, false);
                $this->isTls() ? $this->handshake($client) : $this->serve($client);
            }
        });
    }

    public function stop(): void
    {
        if ($this->watcher !== null) {
            Loop::get()->cancel($this->watcher);
            $this->watcher = null;
        }

        foreach ($this->handshakes as $watcher) {
            Loop::get()->cancel($watcher);
        }

        $this->handshakes = [];

        foreach ($this->connections as $conn) {
            $conn->close();
        }

        $this->connections = [];

        if (is_resource($this->socket)) {
            fclose($this->socket);
        }

        $this->socket = null;
    }

    public function connections(): int
    {
        return count($this->connections);
    }

    /** @return resource */
    private function context()
    {
        if (!$this->isTls()) {
            return stream_context_create();
        }

        return stream_context_create(['ssl' => [
            'local_cert' => $this->cert,
            'local_pk' => $this->key,
            'verify_peer' => false,
            'verify_peer_name' => false,
        ]]);
    }

    /**
     * The TLS handshake, a step at a time: the listener is plain `tcp://` and the crypto is
     * enabled on the accepted socket, because `stream_socket_accept()` on a `tls://` listener
     * does the whole handshake blocking, and a phone on a slow link would hold the loop for
     * every other connection while it did.
     *
     * @param resource $client
     */
    private function handshake($client): void
    {
        $id = ++$this->nextId;
        $step = function () use ($client, $id): void {
            set_error_handler(static fn () => true);

            try {
                $done = stream_socket_enable_crypto($client, true, STREAM_CRYPTO_METHOD_TLS_SERVER);
            } finally {
                restore_error_handler();
            }

            if ($done === 0) {
                return; // needs more bytes; the watcher stays
            }

            Loop::get()->cancel($this->handshakes[$id]);
            unset($this->handshakes[$id]);

            if ($done === true) {
                $this->serve($client);
            } else {
                fclose($client);
            }
        };

        $this->handshakes[$id] = Loop::get()->onReadable($client, $step);
        $step();
    }

    /**
     * One phone connection: read until the header is whole, check the UUID, connect where it
     * says, then relay.
     *
     * @param resource $client
     */
    private function serve($client): void
    {
        $id = ++$this->nextId;
        $head = '';
        $earlyPayload = '';
        $connecting = false;
        $far = null;
        $vision = null;
        $realityState = null;

        $protocol = match (true) {
            $this->isReality() => Reality::class,
            $this->isWs() => Http::class,
            default => Raw::class,
        };

        $phone = new Connection(
            $client,
            onMessage: function (Connection $phone, mixed $chunk) use (&$head, &$earlyPayload, &$connecting, &$far, &$vision, &$realityState): void {
                if (is_array($chunk)) {
                    if (isset($chunk['fallback'])) {
                        // REALITY authentication failed: transparently forward raw bytes to dest
                        $connecting = true;
                        $earlyPayload = (string) $chunk['fallback'];
                        $this->dialTarget(
                            $phone,
                            $this->reality['destHost'],
                            $this->reality['destPort'],
                            $earlyPayload,
                            $connecting,
                            $far,
                            vision: null,
                            realityState: null,
                            sendResponseHeader: false,
                        );

                        return;
                    }

                    $early = WsBinary::handshake($chunk, $phone, $this->wsPath);
                    if ($early === false) {
                        $phone->close();

                        return;
                    }
                    if ($early === '') {
                        return;
                    }
                    $chunk = $early;
                }

                $bytes = (string) $chunk;

                if ($vision !== null) {
                    $unwrapped = $vision->unwrapUplink($bytes);
                    $bytes = $unwrapped['data'];
                    if ($unwrapped['switchedToDirect'] && $realityState !== null) {
                        $realityState->directRead = true;
                    }
                }

                if ($far !== null) {
                    if ($bytes !== '') {
                        $far->sendRaw($bytes);
                    }

                    return;
                }

                if ($connecting) {
                    $earlyPayload .= $bytes;
                    if (strlen($earlyPayload) > TcpConnection::MAX_SEND_BUFFER) {
                        $phone->close();
                    }

                    return;
                }

                $head .= $bytes;
                $request = self::parse($head);

                if ($request === null) {
                    if (strlen($head) > 1024) {
                        $phone->close(); // no VLESS header is this long; this is something else knocking
                    }

                    return;
                }

                if ($request === false || $request['uuid'] !== $this->uuid) {
                    // Wrong protocol or wrong key: the connection just goes away. Saying why
                    // would tell a scanner what is here; staying silent tells it nothing.
                    $phone->close();

                    return;
                }

                if ($request['command'] !== self::CMD_TCP) {
                    Logger::debug("[vless] refused command {$request['command']} (TCP only)");
                    $phone->close();

                    return;
                }

                $head = '';
                $host = $request['host'];
                $port = $request['port'];
                $payload = $request['payload'];

                if ($request['flow'] === Vision::FLOW) {
                    $vision = new Vision($this->uuid);
                    if ($payload !== '') {
                        $unwrapped = $vision->unwrapUplink($payload);
                        $payload = $unwrapped['data'];
                        if ($unwrapped['switchedToDirect'] && $realityState !== null) {
                            $realityState->directRead = true;
                        }
                    }
                } elseif ($request['flow'] !== '') {
                    Logger::debug("[vless] refused unsupported flow {$request['flow']}");
                    $phone->close();

                    return;
                }

                $earlyPayload = $payload;
                $this->dialTarget(
                    $phone,
                    $host,
                    $port,
                    $earlyPayload,
                    $connecting,
                    $far,
                    $vision,
                    $realityState,
                    sendResponseHeader: true,
                );
            },
            onClose: function () use (&$far, $id): void {
                unset($this->connections[$id]);
                $far?->close();
            },
            protocol: $protocol,
        );

        if ($this->isReality()) {
            $realityState = new Reality(
                $this->reality['privateKeyRaw'],
                $this->reality['serverNames'],
                $this->reality['shortIds'],
                $this->reality['maxTimeDiff'],
            );
            Reality::attach($phone, $realityState);
        }

        $this->connections[$id] = $phone;
        $phone->setReadableWatcher(Loop::get()->onReadable($client, static fn () => $phone->onReadable()));
    }

    private function dialTarget(
        Connection $phone,
        string $host,
        int $port,
        string &$earlyPayload,
        bool &$connecting,
        ?Connection &$far,
        ?Vision $vision,
        ?Reality $realityState,
        bool $sendResponseHeader,
    ): void {
        if (self::needsDns($host)) {
            $connecting = true;
            Async::spawn(function () use ($phone, $host, $port, &$earlyPayload, &$connecting, &$far, $vision, $realityState, $sendResponseHeader): void {
                try {
                    $resolved = Dns::resolve($host, 10.0);
                } catch (\Throwable) {
                    $phone->close();

                    return;
                }

                if ($phone->isClosed()) {
                    return;
                }

                $payload = $earlyPayload;
                $earlyPayload = '';
                $connecting = false;
                $far = $this->connect($phone, $resolved, $port, $payload, $vision, $realityState, $sendResponseHeader);

                if ($far === null) {
                    $phone->close();
                }
            });

            return;
        }

        $payload = $earlyPayload;
        $earlyPayload = '';
        $far = $this->connect($phone, $host, $port, $payload, $vision, $realityState, $sendResponseHeader);

        if ($far === null) {
            $phone->close();
        }
    }

    private static function needsDns(string $host): bool
    {
        return strcasecmp($host, 'localhost') !== 0
            && filter_var(trim($host, '[]'), FILTER_VALIDATE_IP) === false;
    }

    /**
     * The far end: connect without waiting, and start relaying once the connect lands.
     *
     * @return Connection|null null when the connect could not even be started
     */
    private function connect(
        Connection $phone,
        string $host,
        int $port,
        string $payload,
        ?Vision $vision = null,
        ?Reality $realityState = null,
        bool $sendResponseHeader = true,
    ): ?Connection {
        $errno = 0;
        $errstr = '';
        $connectHost = strcasecmp($host, 'localhost') === 0 ? '127.0.0.1' : $host;
        $target = str_contains($connectHost, ':') ? "tcp://[{$connectHost}]:{$port}" : "tcp://{$connectHost}:{$port}";

        set_error_handler(static fn () => true);

        try {
            $socket = stream_socket_client($target, $errno, $errstr, 0, STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT);
        } finally {
            restore_error_handler();
        }

        if ($socket === false) {
            Logger::debug("[vless] {$target}: {$errstr}");

            return null;
        }

        stream_set_blocking($socket, false);
        $id = ++$this->nextId;
        $sentResponseHeader = !$sendResponseHeader;

        $far = new Connection(
            $socket,
            onMessage: static function (Connection $far, mixed $chunk) use ($phone, $vision, $realityState, &$sentResponseHeader): void {
                $prefix = '';
                if (!$sentResponseHeader) {
                    $prefix = "\x00\x00";
                    $sentResponseHeader = true;
                }
                if ($vision !== null) {
                    $wrapped = $vision->wrapDownlink((string) $chunk, $prefix);
                    $phone->send($wrapped['framed']);
                    if ($wrapped['switchToDirectAfterSend'] && $realityState !== null) {
                        $realityState->directWrite = true;
                    }

                    return;
                }
                $phone->send($prefix . (string) $chunk);
            },
            onClose: function () use ($phone, $id): void {
                unset($this->connections[$id]);
                $phone->close();
            },
            protocol: Raw::class,
        );

        $this->connections[$id] = $far;

        // Connected or refused shows as writable; `stream_socket_get_name(…, true)` says which.
        $probe = null;
        $probe = Loop::get()->onWritable($socket, function () use (&$probe, $socket, $far, $phone, $payload, $target, $vision, &$sentResponseHeader): void {
            Loop::get()->cancel((string) $probe);

            if (stream_socket_get_name($socket, true) === false) {
                Logger::debug("[vless] {$target}: connect failed");
                $far->close();

                return;
            }

            $far->setReadableWatcher(Loop::get()->onReadable($socket, static fn () => $far->onReadable()));
            if (!$sentResponseHeader && $vision === null) {
                $sentResponseHeader = true;
                $phone->send("\x00\x00"); // the response header: version 0, no addons
            }

            if ($payload !== '') {
                $far->sendRaw($payload);
            }
        });

        return $far;
    }

    /**
     * The request header.
     *
     * @return array{uuid: string, flow: string, command: int, host: string, port: int, payload: string}|null|false
     *         null while the bytes so far are a prefix of a header, false when they cannot be one
     */
    public static function parse(string $bytes): array|null|false
    {
        $length = strlen($bytes);

        if ($length < 1) {
            return null;
        }

        if (ord($bytes[0]) !== 0) {
            return false;
        }

        if ($length < 18) {
            return null;
        }

        $uuid = substr($bytes, 1, 16);
        $addonsLen = ord($bytes[17]);
        $at = 18 + $addonsLen;

        if ($length < $at + 4) {
            return null;
        }

        $flow = $addonsLen > 0 ? Vision::decodeAddonsFlow(substr($bytes, 18, $addonsLen)) : '';
        $command = ord($bytes[$at]);
        $port = unpack('n', substr($bytes, $at + 1, 2))[1];
        $type = ord($bytes[$at + 3]);
        $at += 4;

        switch ($type) {
            case 1:
                if ($length < $at + 4) {
                    return null;
                }

                $host = inet_ntop(substr($bytes, $at, 4)) ?: '';
                $at += 4;
                break;

            case 2:
                if ($length < $at + 1) {
                    return null;
                }

                $size = ord($bytes[$at]);

                if ($length < $at + 1 + $size) {
                    return null;
                }

                $host = substr($bytes, $at + 1, $size);
                $at += 1 + $size;
                break;

            case 3:
                if ($length < $at + 16) {
                    return null;
                }

                $host = inet_ntop(substr($bytes, $at, 16)) ?: '';
                $at += 16;
                break;

            default:
                return false;
        }

        if ($host === '' || $port === 0) {
            return false;
        }

        return [
            'uuid' => $uuid,
            'flow' => $flow,
            'command' => $command,
            'host' => $host,
            'port' => $port,
            'payload' => substr($bytes, $at),
        ];
    }

    /** The link a phone scans or pastes. */
    public function shareLink(string $host, string $name = 'pig'): string
    {
        $uuid = bin2hex($this->uuid);
        $uuid = substr($uuid, 0, 8) . '-' . substr($uuid, 8, 4) . '-' . substr($uuid, 12, 4) . '-' . substr($uuid, 16, 4) . '-' . substr($uuid, 20);

        if ($this->isReality()) {
            $r = $this->reality;
            $sni = $r['serverNames'][0] ?? $r['destHost'];
            $params = [
                'encryption=none',
                'security=reality',
                'type=tcp',
            ];
            if ($r['flow'] !== '') {
                $params[] = 'flow=' . rawurlencode($r['flow']);
            }
            $params[] = 'sni=' . rawurlencode($sni);
            $params[] = 'fp=' . rawurlencode($r['fingerprint']);
            $params[] = 'pbk=' . rawurlencode($r['publicKey']);
            if ($r['primaryShortIdHex'] !== '') {
                $params[] = 'sid=' . rawurlencode($r['primaryShortIdHex']);
            }

            return "vless://{$uuid}@{$host}:{$this->port}?" . implode('&', $params) . '#' . rawurlencode($name);
        }

        $security = $this->isTls() ? 'tls' : 'none';
        $transport = $this->wsPath !== null
            ? 'type=ws&path=' . rawurlencode($this->wsPath)
            : 'type=tcp';

        return "vless://{$uuid}@{$host}:{$this->port}?encryption=none&security={$security}&{$transport}#" . rawurlencode($name);
    }
}
