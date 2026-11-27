<?php

declare(strict_types=1);

namespace PigVless;

/**
 * XTLS Vision (`xtls-rprx-vision`, `github.com/XTLS/Xray-core/proxy/proxy.go`):
 * - Unpads uplink/downlink Vision padding blocks (`[UUID(16, first block only)] [cmd(1)] [contentLen(2)] [paddingLen(2)] [content] [padding]`).
 * - Pads downlink handshake traffic with randomized lengths (`testseed = [900, 500, 900, 256]`) to mask VLESS + inner TLS handshake lengths.
 * - Filters the first 8 inner packets to detect inner TLS 1.3 (`supported_versions = 0x0304`, non-CCM-8 cipher).
 * - Switches uplink and downlink independently to zero-copy direct splice (`CommandPaddingDirect = 2`, bypassing outer TLS 1.3 AEAD) as soon as inner TLS 1.3 reaches `ApplicationData` (`0x17 0x03 0x03`).
 */
final class Vision
{
    public const string FLOW = 'xtls-rprx-vision';

    public const int CMD_CONTINUE = 0;

    public const int CMD_END = 1;

    public const int CMD_DIRECT = 2;

    private const string TLS_CLIENT_HANDSHAKE_START = "\x16\x03";

    private const string TLS_SERVER_HANDSHAKE_START = "\x16\x03\x03";

    private const string TLS_APP_DATA_START = "\x17\x03\x03";

    private const string TLS13_SUPPORTED_VERSIONS = "\x00\x2b\x00\x02\x03\x04";

    /** @var array<int, bool> TLS 1.3 cipher suites eligible for Vision direct splice */
    private const array TLS13_SPLICE_CIPHERS = [
        0x1301 => true, // TLS_AES_128_GCM_SHA256
        0x1302 => true, // TLS_AES_256_GCM_SHA384
        0x1303 => true, // TLS_CHACHA20_POLY1305_SHA256
        0x1304 => true, // TLS_AES_128_CCM_SHA256
    ];

    public int $packetsToFilter = 8;

    public bool $isTls = false;

    public bool $isTls12OrAbove = false;

    public bool $enableXtls = false;

    public int $cipher = 0;

    public int $remainingServerHello = -1;

    // Inbound uplink reader state
    public bool $withinPadding = true;

    public bool $uplinkDirectCopy = false;

    private bool $seenUuid = false;

    private int $remCmd = -1;

    private int $remContent = -1;

    private int $remPad = -1;

    private int $curCmd = 0;

    private string $cmdBuf = '';

    // Inbound downlink writer state
    public bool $isPadding = true;

    public bool $downlinkDirectCopy = false;

    private bool $wroteUuid = false;

    /** @var array{0: int, 1: int, 2: int, 3: int} */
    private readonly array $testseed;

    /**
     * @param string $userUuid 16-byte binary UUID
     * @param array{0: int, 1: int, 2: int, 3: int} $testseed
     */
    public function __construct(
        private readonly string $userUuid,
        array $testseed = [900, 500, 900, 256],
    ) {
        $this->testseed = $testseed;
    }

    /**
     * Decode VLESS request addons protobuf (`message Addons { string Flow = 1; bytes Seed = 2; }`).
     */
    public static function decodeAddonsFlow(string $addonsBytes): string
    {
        $len = strlen($addonsBytes);
        $at = 0;
        while ($at < $len) {
            $tag = ord($addonsBytes[$at++]);
            $field = $tag >> 3;
            $wire = $tag & 0x07;
            if ($wire !== 2) {
                break;
            }
            $vLen = 0;
            $shift = 0;
            while ($at < $len) {
                $b = ord($addonsBytes[$at++]);
                $vLen |= ($b & 0x7F) << $shift;
                if (($b & 0x80) === 0) {
                    break;
                }
                $shift += 7;
            }
            if ($at + $vLen > $len) {
                break;
            }
            $val = substr($addonsBytes, $at, $vLen);
            $at += $vLen;
            if ($field === 1) {
                return $val;
            }
        }

        return '';
    }

    /**
     * Encode VLESS request addons protobuf for `flow = xtls-rprx-vision` (2 + 16 = 18 bytes).
     */
    public static function encodeAddonsFlow(string $flow = self::FLOW): string
    {
        return $flow === '' ? '' : "\x0a" . chr(strlen($flow)) . $flow;
    }

    /**
     * Unpad uplink bytes from the client, filter TLS handshake packets, and report whether
     * uplink switched to direct raw copy on this chunk.
     *
     * @return array{data: string, switchedToDirect: bool}
     */
    public function unwrapUplink(string $chunk): array
    {
        if ($chunk === '') {
            return ['data' => '', 'switchedToDirect' => false];
        }
        if ($this->uplinkDirectCopy) {
            return ['data' => $chunk, 'switchedToDirect' => false];
        }

        $out = $chunk;
        $switched = false;

        if ($this->withinPadding || $this->packetsToFilter > 0) {
            $out = $this->unpad($chunk);

            if ($this->remContent > 0 || $this->remPad > 0 || $this->curCmd === self::CMD_CONTINUE) {
                $this->withinPadding = true;
            } elseif ($this->curCmd === self::CMD_END) {
                $this->withinPadding = false;
            } elseif ($this->curCmd === self::CMD_DIRECT) {
                $this->withinPadding = false;
                $this->uplinkDirectCopy = true;
                $switched = true;
            }
        }

        if ($this->packetsToFilter > 0 && $out !== '') {
            $this->filterTls($out);
        }

        return ['data' => $out, 'switchedToDirect' => $switched];
    }

    /**
     * Filter and pad downlink bytes going to the client, and report whether downlink should
     * switch to direct raw copy after sending the returned frame(s).
     *
     * @param string $vlessResponseHeader `"\x00\x00"` on the very first downlink write, or `""` thereafter
     * @return array{framed: string, switchToDirectAfterSend: bool}
     */
    public function wrapDownlink(string $chunk, string $vlessResponseHeader = ''): array
    {
        if ($chunk !== '' && $this->packetsToFilter > 0) {
            $this->filterTls($chunk);
        }

        if (!$this->isPadding) {
            return ['framed' => $vlessResponseHeader . $chunk, 'switchToDirectAfterSend' => false];
        }

        if ($chunk === '') {
            $padded = $this->padBlock('', self::CMD_CONTINUE, true);

            return ['framed' => $vlessResponseHeader . $padded, 'switchToDirectAfterSend' => false];
        }

        $isComplete = self::isCompleteTlsAppDataRecord($chunk);
        $buffers = self::reshapeBuffer($chunk);
        $longPadding = $this->isTls;
        $out = $vlessResponseHeader;
        $switchAfter = false;
        $count = count($buffers);

        foreach ($buffers as $i => $b) {
            $isLast = $i === $count - 1;
            if ($this->isTls && strlen($b) >= 6 && str_starts_with($b, self::TLS_APP_DATA_START) && $isComplete) {
                if ($this->enableXtls) {
                    $switchAfter = true;
                }
                $cmd = self::CMD_CONTINUE;
                if ($isLast) {
                    $cmd = $this->enableXtls ? self::CMD_DIRECT : self::CMD_END;
                }
                $out .= $this->padBlock($b, $cmd, true);
                $this->isPadding = false;
                $longPadding = false;
                continue;
            }

            if (!$this->isTls12OrAbove && $this->packetsToFilter <= 1) {
                $this->isPadding = false;
                $out .= $this->padBlock($b, self::CMD_END, $longPadding);
                $rest = array_slice($buffers, $i + 1);
                if ($rest !== []) {
                    $out .= implode('', $rest);
                }
                break;
            }

            $cmd = self::CMD_CONTINUE;
            if ($isLast && !$this->isPadding) {
                $cmd = $this->enableXtls ? self::CMD_DIRECT : self::CMD_END;
            }
            $out .= $this->padBlock($b, $cmd, $longPadding);
        }

        if ($switchAfter) {
            $this->downlinkDirectCopy = true;
        }

        return ['framed' => $out, 'switchToDirectAfterSend' => $switchAfter];
    }

    /**
     * Build a Vision-padded block (`[UUID(16)]? [cmd(1)] [contentLen(2)] [padLen(2)] [content] [pad]`).
     */
    public function padBlock(string $content, int $command, bool $longPadding = true, ?int $fixedPadLen = null): string
    {
        $contentLen = strlen($content);
        if ($fixedPadLen !== null) {
            $padLen = $fixedPadLen;
        } elseif ($contentLen < $this->testseed[0] && $longPadding) {
            $padLen = random_int(0, $this->testseed[1] - 1) + $this->testseed[2] - $contentLen;
        } else {
            $padLen = random_int(0, $this->testseed[3] - 1);
        }
        $maxPad = max(0, 8192 - 21 - $contentLen);
        if ($padLen > $maxPad) {
            $padLen = $maxPad;
        }
        if ($padLen < 0) {
            $padLen = 0;
        }

        $prefix = '';
        if (!$this->wroteUuid) {
            $prefix = $this->userUuid;
            $this->wroteUuid = true;
        }

        return $prefix
            . pack('Cnn', $command, $contentLen, $padLen)
            . $content
            . ($padLen > 0 ? str_repeat("\x00", $padLen) : '');
    }

    /**
     * Inspect inner traffic for TLS 1.2 / TLS 1.3 ClientHello and ServerHello (`XtlsFilterTls`).
     */
    public function filterTls(string $chunk): void
    {
        if ($this->packetsToFilter <= 0 || $chunk === '') {
            return;
        }
        $this->packetsToFilter--;
        $len = strlen($chunk);

        if ($len >= 6) {
            if (str_starts_with($chunk, self::TLS_SERVER_HANDSHAKE_START) && $chunk[5] === "\x02") {
                $this->remainingServerHello = (unpack('n', substr($chunk, 3, 2))[1]) + 5;
                $this->isTls12OrAbove = true;
                $this->isTls = true;
                if ($len >= 79 && $this->remainingServerHello >= 79) {
                    $sidLen = ord($chunk[43]);
                    if ($len >= 43 + $sidLen + 3) {
                        $this->cipher = unpack('n', substr($chunk, 44 + $sidLen, 2))[1];
                    }
                }
            } elseif (str_starts_with($chunk, self::TLS_CLIENT_HANDSHAKE_START) && $chunk[5] === "\x01") {
                $this->isTls = true;
            }
        }

        if ($this->remainingServerHello > 0) {
            $end = min($this->remainingServerHello, $len);
            $this->remainingServerHello -= $len;
            if (str_contains(substr($chunk, 0, $end), self::TLS13_SUPPORTED_VERSIONS)) {
                if (isset(self::TLS13_SPLICE_CIPHERS[$this->cipher])) {
                    $this->enableXtls = true;
                }
                $this->packetsToFilter = 0;

                return;
            }
            if ($this->remainingServerHello <= 0) {
                $this->packetsToFilter = 0;
            }
        }
    }

    /**
     * Whether `$bytes` consists entirely of one or more complete TLS ApplicationData records (`0x17 0x03 0x03`).
     */
    public static function isCompleteTlsAppDataRecord(string $bytes): bool
    {
        $total = strlen($bytes);
        if ($total < 6) {
            return false;
        }
        $at = 0;
        while ($at < $total) {
            if ($total - $at < 5) {
                return false;
            }
            if ($bytes[$at] !== "\x17" || $bytes[$at + 1] !== "\x03" || $bytes[$at + 2] !== "\x03") {
                return false;
            }
            $recLen = unpack('n', substr($bytes, $at + 3, 2))[1];
            if ($recLen <= 0 || $total - ($at + 5) < $recLen) {
                return false;
            }
            $at += 5 + $recLen;
        }

        return $at === $total;
    }

    /**
     * Split buffers >= 8171 bytes on TLS ApplicationData boundaries (`ReshapeMultiBuffer`).
     *
     * @return list<string>
     */
    private static function reshapeBuffer(string $bytes): array
    {
        $limit = 8192 - 21;
        if (strlen($bytes) < $limit) {
            return [$bytes];
        }
        $out = [];
        while (strlen($bytes) >= $limit) {
            $slice = substr($bytes, 0, $limit);
            $idx = strrpos($slice, self::TLS_APP_DATA_START);
            if ($idx === false || $idx < 21) {
                $idx = 4096;
            }
            $out[] = substr($bytes, 0, $idx);
            $bytes = substr($bytes, $idx);
        }
        if ($bytes !== '') {
            $out[] = $bytes;
        }

        return $out;
    }

    private function unpad(string $chunk): string
    {
        if ($this->remCmd === -1 && $this->remContent === -1 && $this->remPad === -1) {
            if (!$this->seenUuid) {
                if (strlen($chunk) >= 21 && substr($chunk, 0, 16) === $this->userUuid) {
                    $this->seenUuid = true;
                    $chunk = substr($chunk, 16);
                    $this->remCmd = 5;
                    $this->cmdBuf = '';
                } else {
                    return $chunk;
                }
            } else {
                return $chunk;
            }
        }

        $out = '';
        $at = 0;
        $len = strlen($chunk);

        while ($at < $len) {
            if ($this->remCmd > 0) {
                $take = min($this->remCmd, $len - $at);
                $this->cmdBuf .= substr($chunk, $at, $take);
                $at += $take;
                $this->remCmd -= $take;
                if ($this->remCmd === 0) {
                    $u = unpack('Ccmd/ncontent/npad', $this->cmdBuf);
                    $this->curCmd = $u['cmd'];
                    $this->remContent = $u['content'];
                    $this->remPad = $u['pad'];
                    $this->cmdBuf = '';
                }
            } elseif ($this->remContent > 0) {
                $take = min($this->remContent, $len - $at);
                $out .= substr($chunk, $at, $take);
                $at += $take;
                $this->remContent -= $take;
            } elseif ($this->remPad > 0) {
                $take = min($this->remPad, $len - $at);
                $at += $take;
                $this->remPad -= $take;
            }

            if ($this->remCmd <= 0 && $this->remContent <= 0 && $this->remPad <= 0) {
                if ($this->curCmd === self::CMD_CONTINUE) {
                    $this->remCmd = 5;
                    $this->cmdBuf = '';
                } else {
                    $this->remCmd = -1;
                    $this->remContent = -1;
                    $this->remPad = -1;
                    if ($at < $len) {
                        $out .= substr($chunk, $at);
                    }
                    break;
                }
            }
        }

        return $out;
    }
}
