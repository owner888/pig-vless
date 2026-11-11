<?php

declare(strict_types=1);

namespace PigVless;

use Pig\CodingAgent\Web\Protocols\ProtocolInterface;
use Pig\CodingAgent\Web\TcpConnection;

/** Bytes in, bytes out: `TcpConnection` without a frame. */
final class Raw implements ProtocolInterface
{
    public static function input(string $buffer, TcpConnection $connection): int|false
    {
        return strlen($buffer);
    }

    public static function decode(string $buffer, TcpConnection $connection): mixed
    {
        return $buffer;
    }

    public static function encode(mixed $data, TcpConnection $connection): string
    {
        return (string) $data;
    }
}
