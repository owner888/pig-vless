<?php

declare(strict_types=1);

namespace PigVless;

use Pig\CodingAgent\Web\Protocols\ProtocolInterface;
use Pig\CodingAgent\Web\Protocols\Websocket;
use Pig\CodingAgent\Web\TcpConnection;

/**
 * VLESS over WebSocket: RFC 6455 binary frames (`OPCODE_BINARY`), with Xray/v2ray 0-RTT early
 * data accepted from `Sec-WebSocket-Protocol`.
 */
final class WsBinary implements ProtocolInterface
{
    private const string GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

    /**
     * Upgrade an HTTP request on `$expectedPath` to binary WebSocket frames.
     *
     * @param array{path?: string, headers?: array<string, string>} $request
     * @return string|false early-data bytes from `Sec-WebSocket-Protocol` (empty when none), or false on refusal
     */
    public static function handshake(array $request, TcpConnection $connection, ?string $expectedPath = null): string|false
    {
        if ($expectedPath !== null && ($request['path'] ?? '') !== $expectedPath) {
            return false;
        }

        $headers = $request['headers'] ?? [];
        $upgrade = strtolower($headers['upgrade'] ?? '');
        $connectionHeader = strtolower($headers['connection'] ?? '');
        $key = $headers['sec-websocket-key'] ?? null;

        if ($upgrade !== 'websocket' || !str_contains($connectionHeader, 'upgrade') || $key === null) {
            return false;
        }

        $earlyData = '';
        $protocol = trim($headers['sec-websocket-protocol'] ?? '');
        if ($protocol !== '') {
            $decoded = base64_decode(strtr($protocol, '-_', '+/'), true);
            if ($decoded === false) {
                return false;
            }
            $earlyData = $decoded;
        }

        $accept = base64_encode(sha1($key . self::GUID, true));
        $connection->sendRaw(
            "HTTP/1.1 101 Switching Protocols\r\n"
            . "Upgrade: websocket\r\n"
            . "Connection: Upgrade\r\n"
            . "Sec-WebSocket-Accept: {$accept}\r\n\r\n",
        );
        $connection->setProtocol(self::class);

        return $earlyData;
    }

    public static function input(string $buffer, TcpConnection $connection): int|false
    {
        return Websocket::input($buffer, $connection);
    }

    public static function decode(string $buffer, TcpConnection $connection): ?string
    {
        return Websocket::decode($buffer, $connection);
    }

    public static function encode(mixed $data, TcpConnection $connection): string
    {
        return Websocket::createFrame((string) $data, Websocket::OPCODE_BINARY);
    }
}
