<?php

declare(strict_types=1);

namespace PigVless;

use InvalidArgumentException;
use OpenSSLAsymmetricKey;
use Pig\CodingAgent\Web\Protocols\ProtocolInterface;
use Pig\CodingAgent\Web\TcpConnection;
use RuntimeException;

/**
 * Pure-PHP TLS 1.3 + REALITY record-layer protocol (`ProtocolInterface` over a plain `tcp://`
 * `TcpConnection`), using `ext-openssl` primitives (X25519 ECDH, Ed25519 signature, HKDF-SHA256/384,
 * AES-128-GCM / AES-256-GCM / ChaCha20-Poly1305) and supporting XTLS Vision zero-copy splice
 * (`enableDirectRead()` / `enableDirectWrite()`).
 *
 * Handshake and authentication follow `github.com/XTLS/REALITY` and `github.com/XTLS/Xray-core`:
 * - Parses the client's TLS 1.3 `ClientHello`: `random` (32B), `session_id` (32B), `cipher_suites`,
 *   `server_name` (SNI), `alpn`, `supported_versions`, and `key_share` (`X25519` `0x001d` or the
 *   trailing 32-byte X25519 share of hybrid `X25519MLKEM768` `0x11ec`).
 * - Derives `AuthKey = HKDF-SHA256(ECDH(serverPrivateKey, clientX25519Share), salt: random[0..20], info: "REALITY", len: 32)`
 *   and opens `session_id` with `AES-256-GCM(key: AuthKey, nonce: random[20..32], aad: ClientHelloWithZeroedSessionId)`
 *   to verify `shortId` and timestamp.
 * - On authentication failure, returns `['fallback' => $rawRecord]` so `VlessServer` transparently
 *   relays the connection to the real `$dest` server (indistinguishable from the real site to active
 *   probers).
 * - On authentication success, completes the TLS 1.3 handshake with a temporary Ed25519 X.509 certificate
 *   whose 64-byte signature is `HMAC-SHA512(key: AuthKey, data: tempEd25519PublicKey)`, as Xray's
 *   `UConn.VerifyPeerCertificate` verifies.
 */
final class Reality implements ProtocolInterface
{
    public const int GROUP_X25519 = 0x001D;

    public const int GROUP_X25519_MLKEM768 = 0x11EC;

    public const int TLS_AES_128_GCM_SHA256 = 0x1301;

    public const int TLS_AES_256_GCM_SHA384 = 0x1302;

    public const int TLS_CHACHA20_POLY1305_SHA256 = 0x1303;

    /** ASN.1 SubjectPublicKeyInfo prefix for a 32-byte X25519 public key (OID 1.3.101.110). */
    private const string X25519_SPKI_PREFIX = "\x30\x2a\x30\x05\x06\x03\x2b\x65\x6e\x03\x21\x00";

    /** ASN.1 PKCS#8 PrivateKeyInfo prefix for a 32-byte X25519 private key (OID 1.3.101.110). */
    private const string X25519_PKCS8_PREFIX = "\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x6e\x04\x22\x04\x20";

    /** @var \WeakMap<TcpConnection, self>|null */
    private static ?\WeakMap $states = null;

    private static ?OpenSSLAsymmetricKey $ed25519Key = null;

    private static string $ed25519PubRaw = '';

    public const int STATE_CLIENT_HELLO = 0;

    public const int STATE_CLIENT_FINISHED = 1;

    public const int STATE_APPLICATION = 2;

    public const int STATE_FALLBACK = 3;

    public int $state = self::STATE_CLIENT_HELLO;

    public bool $directRead = false;

    public bool $directWrite = false;

    public string $cipherMethod = 'aes-128-gcm';

    public string $hashAlgo = 'sha256';

    public int $hashLen = 32;

    public int $keyLen = 16;

    public string $clientHsKey = '';

    public string $clientHsIv = '';

    public int $clientHsSeq = 0;

    public string $clientAppKey = '';

    public string $clientAppIv = '';

    public int $clientAppSeq = 0;

    public string $serverAppKey = '';

    public string $serverAppIv = '';

    public int $serverAppSeq = 0;

    public string $expectedClientFinished = '';

    /**
     * @param string            $privateKeyRaw 32-byte X25519 private key
     * @param list<string>      $serverNames   allowed SNIs (empty allows any)
     * @param list<string>      $shortIds      allowed 8-byte binary shortIds
     * @param int               $maxTimeDiff   maximum clock skew in seconds (0 disables check)
     */
    public function __construct(
        private readonly string $privateKeyRaw,
        private readonly array $serverNames = [],
        private readonly array $shortIds = ["\x00\x00\x00\x00\x00\x00\x00\x00"],
        private readonly int $maxTimeDiff = 0,
    ) {
    }

    public static function attach(TcpConnection $connection, self $state): void
    {
        self::$states ??= new \WeakMap();
        self::$states[$connection] = $state;
    }

    public static function of(TcpConnection $connection): ?self
    {
        return self::$states?->offsetExists($connection) ? self::$states[$connection] : null;
    }

    /**
     * Generate a fresh X25519 key pair encoded in Xray's base64url (no padding) format.
     *
     * @return array{privateKey: string, publicKey: string}
     */
    public static function generateKeyPair(): array
    {
        $pkey = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_X25519]);
        if ($pkey === false) {
            throw new RuntimeException('Failed to generate X25519 key pair');
        }
        $details = openssl_pkey_get_details($pkey);
        $priv = (string) ($details['x25519']['priv_key'] ?? '');
        $pub = (string) ($details['x25519']['pub_key'] ?? '');
        if (strlen($priv) !== 32 || strlen($pub) !== 32) {
            throw new RuntimeException('Invalid X25519 key details from OpenSSL');
        }

        return [
            'privateKey' => self::base64UrlEncode($priv),
            'publicKey' => self::base64UrlEncode($pub),
        ];
    }

    /** Derive the 32-byte X25519 public key from a 32-byte raw private key. */
    public static function publicKeyFromPrivate(string $privateKeyRaw): string
    {
        if (strlen($privateKeyRaw) !== 32) {
            throw new InvalidArgumentException('X25519 private key must be 32 bytes');
        }
        if (function_exists('sodium_crypto_scalarmult_base')) {
            return sodium_crypto_scalarmult_base($privateKeyRaw);
        }
        $pkey = self::loadPrivateKey($privateKeyRaw);
        $details = openssl_pkey_get_details($pkey);

        return (string) ($details['x25519']['pub_key'] ?? '');
    }

    /** Decode a base64url / base64 / hex X25519 key into 32 raw bytes. */
    public static function decodeKey(string $encoded): string
    {
        $trimmed = trim($encoded);
        if (strlen($trimmed) === 64 && ctype_xdigit($trimmed)) {
            return (string) hex2bin($trimmed);
        }
        $raw = base64_decode(strtr($trimmed, '-_', '+/'), true);
        if ($raw === false || strlen($raw) !== 32) {
            throw new InvalidArgumentException('Invalid X25519 key (expected 32-byte base64url or hex)');
        }

        return $raw;
    }

    /** Decode a hex shortId (0..16 hex chars) into an 8-byte zero-padded binary shortId. */
    public static function decodeShortId(string $hex): string
    {
        $trimmed = strtolower(trim($hex));
        if ($trimmed === '') {
            return str_repeat("\x00", 8);
        }
        if (strlen($trimmed) > 16 || !ctype_xdigit($trimmed)) {
            throw new InvalidArgumentException("Invalid REALITY shortId: {$hex}");
        }

        return (string) hex2bin(str_pad($trimmed, 16, '0', STR_PAD_RIGHT));
    }

    public static function base64UrlEncode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /** Compute X25519 ECDH shared secret (32 bytes). */
    public static function x25519Ecdh(string $privateKeyRaw, string $peerPublicKeyRaw): string|false
    {
        if (strlen($privateKeyRaw) !== 32 || strlen($peerPublicKeyRaw) !== 32) {
            return false;
        }
        $priv = self::loadPrivateKey($privateKeyRaw);
        $pubPem = "-----BEGIN PUBLIC KEY-----\n"
            . base64_encode(self::X25519_SPKI_PREFIX . $peerPublicKeyRaw)
            . "\n-----END PUBLIC KEY-----\n";

        set_error_handler(static fn (): bool => true);
        try {
            $shared = openssl_pkey_derive($pubPem, $priv);
        } finally {
            restore_error_handler();
        }

        return is_string($shared) && strlen($shared) === 32 ? $shared : false;
    }

    /** TLS 1.3 `HKDF-Expand-Label(Secret, Label, Context, Length)` (RFC 8446 §7.1). */
    public static function hkdfExpandLabel(string $algo, string $secret, string $label, string $context, int $length): string
    {
        $fullLabel = 'tls13 ' . $label;
        $info = pack('nC', $length, strlen($fullLabel)) . $fullLabel . chr(strlen($context)) . $context;

        return self::hkdfExpand($algo, $secret, $info, $length);
    }

    /** RFC 5869 `HKDF-Extract(salt, IKM)`. */
    public static function hkdfExtract(string $algo, string $salt, string $ikm): string
    {
        $hashLen = $algo === 'sha384' ? 48 : 32;
        if ($salt === '') {
            $salt = str_repeat("\x00", $hashLen);
        }
        if ($ikm === '') {
            $ikm = str_repeat("\x00", $hashLen);
        }

        return hash_hmac($algo, $ikm, $salt, true);
    }

    /** RFC 5869 `HKDF-Expand(PRK, info, L)`. */
    public static function hkdfExpand(string $algo, string $prk, string $info, int $length): string
    {
        $okm = '';
        $t = '';
        for ($i = 1; strlen($okm) < $length; $i++) {
            $t = hash_hmac($algo, $t . $info . chr($i), $prk, true);
            $okm .= $t;
        }

        return substr($okm, 0, $length);
    }

    public static function deriveSecret(string $algo, string $secret, string $label, string $transcriptBytes): string
    {
        $hashLen = $algo === 'sha384' ? 48 : 32;

        return self::hkdfExpandLabel($algo, $secret, $label, hash($algo, $transcriptBytes, true), $hashLen);
    }

    public static function aeadNonce(string $iv, int $seq): string
    {
        $seqBytes = str_repeat("\x00", 4) . pack('J', $seq);

        return $iv ^ $seqBytes;
    }

    public static function encryptRecord(
        string $cipherMethod,
        string $key,
        string $iv,
        int &$seq,
        string $innerPlaintext,
        int $innerContentType = 0x17,
        int $padZeros = 0,
    ): string {
        $inner = $innerPlaintext . chr($innerContentType) . ($padZeros > 0 ? str_repeat("\x00", $padZeros) : '');
        $encryptedLen = strlen($inner) + 16;
        $header = "\x17\x03\x03" . pack('n', $encryptedLen);
        $nonce = self::aeadNonce($iv, $seq);
        $seq++;
        $tag = '';
        $ciphertext = openssl_encrypt($inner, $cipherMethod, $key, OPENSSL_RAW_DATA, $nonce, $tag, $header, 16);
        if ($ciphertext === false) {
            throw new RuntimeException('TLS 1.3 AEAD seal failed');
        }

        return $header . $ciphertext . $tag;
    }

    /**
     * @return array{type: int, content: string}|false
     */
    public static function decryptRecord(
        string $cipherMethod,
        string $key,
        string $iv,
        int &$seq,
        string $record,
    ): array|false {
        if (strlen($record) < 22 || $record[0] !== "\x17") {
            return false;
        }
        $header = substr($record, 0, 5);
        $body = substr($record, 5);
        $ciphertext = substr($body, 0, -16);
        $tag = substr($body, -16);
        $nonce = self::aeadNonce($iv, $seq);
        $seq++;

        set_error_handler(static fn (): bool => true);
        try {
            $plain = openssl_decrypt($ciphertext, $cipherMethod, $key, OPENSSL_RAW_DATA, $nonce, $tag, $header);
        } finally {
            restore_error_handler();
        }
        if ($plain === false) {
            return false;
        }
        $trimmed = rtrim($plain, "\x00");
        if ($trimmed === '') {
            return false;
        }

        return [
            'type' => ord($trimmed[strlen($trimmed) - 1]),
            'content' => substr($trimmed, 0, -1),
        ];
    }

    public static function input(string $buffer, TcpConnection $connection): int|false
    {
        $self = self::of($connection);
        if ($self === null || $self->directRead || $self->state === self::STATE_FALLBACK) {
            return strlen($buffer);
        }
        if (strlen($buffer) < 5) {
            return 0;
        }
        $type = ord($buffer[0]);
        if ($type < 0x14 || $type > 0x18) {
            // Non-TLS bytes on initial packet -> hand entire buffer to fallback
            return $self->state === self::STATE_CLIENT_HELLO ? strlen($buffer) : false;
        }
        $len = unpack('n', substr($buffer, 3, 2))[1];
        if ($len > 32768) {
            return $self->state === self::STATE_CLIENT_HELLO ? strlen($buffer) : false;
        }
        $total = 5 + $len;

        return strlen($buffer) >= $total ? $total : 0;
    }

    public static function decode(string $buffer, TcpConnection $connection): mixed
    {
        $self = self::of($connection);
        if ($self === null || $self->directRead || $self->state === self::STATE_FALLBACK) {
            return $buffer;
        }

        if ($self->state === self::STATE_CLIENT_HELLO) {
            return $self->handleClientHello($buffer, $connection);
        }

        // Ignore TLS 1.3 middlebox compatibility ChangeCipherSpec record (0x14 0x03 0x03 0x00 0x01 0x01)
        if ($buffer[0] === "\x14") {
            return null;
        }

        if ($self->state === self::STATE_CLIENT_FINISHED) {
            $dec = self::decryptRecord($self->cipherMethod, $self->clientHsKey, $self->clientHsIv, $self->clientHsSeq, $buffer);
            if ($dec === false || $dec['type'] !== 0x16) {
                $connection->close();

                return null;
            }
            $expectedMsg = "\x14" . substr(pack('N', strlen($self->expectedClientFinished)), 1, 3) . $self->expectedClientFinished;
            if (!hash_equals($expectedMsg, $dec['content'])) {
                $connection->close();

                return null;
            }
            $self->state = self::STATE_APPLICATION;

            return null;
        }

        $dec = self::decryptRecord($self->cipherMethod, $self->clientAppKey, $self->clientAppIv, $self->clientAppSeq, $buffer);
        if ($dec === false) {
            $connection->close();

            return null;
        }
        if ($dec['type'] === 0x15) {
            // Alert (e.g. close_notify)
            $connection->close();

            return null;
        }
        if ($dec['type'] !== 0x17) {
            return null;
        }

        return $dec['content'];
    }

    public static function encode(mixed $data, TcpConnection $connection): string
    {
        $bytes = (string) $data;
        if ($bytes === '') {
            return '';
        }
        $self = self::of($connection);
        if ($self === null || $self->directWrite || $self->state !== self::STATE_APPLICATION) {
            return $bytes;
        }

        $out = '';
        foreach (str_split($bytes, 16384) as $chunk) {
            $out .= self::encryptRecord($self->cipherMethod, $self->serverAppKey, $self->serverAppIv, $self->serverAppSeq, $chunk, 0x17);
        }

        return $out;
    }

    /**
     * Validate a REALITY TLS 1.3 ClientHello record, or return `['fallback' => $rawRecord]` if it is
     * an unauthorized probe/browser.
     *
     * @return array{fallback: string}|null
     */
    private function handleClientHello(string $record, TcpConnection $connection): ?array
    {
        $parsed = self::parseClientHelloRecord($record);
        if ($parsed === null) {
            $this->state = self::STATE_FALLBACK;

            return ['fallback' => $record];
        }

        // 1. Check TLS 1.3 support & SNI
        if (!in_array(0x0304, $parsed['versions'], true)) {
            $this->state = self::STATE_FALLBACK;

            return ['fallback' => $record];
        }
        if ($this->serverNames !== [] && !in_array(strtolower($parsed['sni']), $this->serverNames, true)) {
            $this->state = self::STATE_FALLBACK;

            return ['fallback' => $record];
        }

        // 2. Locate client's X25519 key share (pure X25519 0x001d or trailing 32B of X25519MLKEM768 0x11ec)
        $clientPub = $parsed['x25519Share'];
        if ($clientPub === null || strlen($parsed['sessionId']) !== 32) {
            $this->state = self::STATE_FALLBACK;

            return ['fallback' => $record];
        }

        // 3. REALITY ECDH + HKDF-SHA256 + AES-256-GCM sessionId authentication
        $ecdh = self::x25519Ecdh($this->privateKeyRaw, $clientPub);
        if ($ecdh === false) {
            $this->state = self::STATE_FALLBACK;

            return ['fallback' => $record];
        }
        $prk = self::hkdfExtract('sha256', substr($parsed['random'], 0, 20), $ecdh);
        $authKey = self::hkdfExpand('sha256', $prk, 'REALITY', 32);

        $nonce = substr($parsed['random'], 20, 12);
        $ciphertext = substr($parsed['sessionId'], 0, 16);
        $tag = substr($parsed['sessionId'], 16, 16);
        $aad = $parsed['rawHandshakeZeroedSid'];

        set_error_handler(static fn (): bool => true);
        try {
            $plain = openssl_decrypt($ciphertext, 'aes-256-gcm', $authKey, OPENSSL_RAW_DATA, $nonce, $tag, $aad);
        } finally {
            restore_error_handler();
        }
        if ($plain === false || strlen($plain) !== 16) {
            $this->state = self::STATE_FALLBACK;

            return ['fallback' => $record];
        }

        $clientTime = unpack('N', substr($plain, 4, 4))[1];
        $clientShortId = substr($plain, 8, 8);

        if ($this->maxTimeDiff > 0 && abs(time() - $clientTime) > $this->maxTimeDiff) {
            $this->state = self::STATE_FALLBACK;

            return ['fallback' => $record];
        }
        if (!in_array($clientShortId, $this->shortIds, true)) {
            $this->state = self::STATE_FALLBACK;

            return ['fallback' => $record];
        }

        // 4. Pick TLS 1.3 cipher suite
        $chosenSuite = self::TLS_AES_128_GCM_SHA256;
        foreach ([self::TLS_AES_128_GCM_SHA256, self::TLS_CHACHA20_POLY1305_SHA256, self::TLS_AES_256_GCM_SHA384] as $pref) {
            if (in_array($pref, $parsed['cipherSuites'], true)) {
                $chosenSuite = $pref;
                break;
            }
        }
        [$this->cipherMethod, $this->hashAlgo, $this->hashLen, $this->keyLen] = match ($chosenSuite) {
            self::TLS_AES_256_GCM_SHA384 => ['aes-256-gcm', 'sha384', 48, 32],
            self::TLS_CHACHA20_POLY1305_SHA256 => ['chacha20-poly1305', 'sha256', 32, 32],
            default => ['aes-128-gcm', 'sha256', 32, 16],
        };

        // 5. Generate ephemeral server X25519 key share and build ServerHello
        $eph = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_X25519]);
        if ($eph === false) {
            $connection->close();

            return null;
        }
        $ephDetails = openssl_pkey_get_details($eph);
        $serverEphPriv = (string) $ephDetails['x25519']['priv_key'];
        $serverEphPub = (string) $ephDetails['x25519']['pub_key'];
        $tlsShared = self::x25519Ecdh($serverEphPriv, $clientPub);
        if ($tlsShared === false) {
            $connection->close();

            return null;
        }

        // ServerHello extensions: supported_versions (0x002b = 0x0304) + key_share (0x0033 = X25519 32B)
        $shExts = pack('nnn', 0x002B, 2, 0x0304)
            . pack('nnnn', 0x0033, 36, self::GROUP_X25519, 32) . $serverEphPub;
        $shBody = "\x03\x03"
            . random_bytes(32)
            . chr(strlen($parsed['sessionId'])) . $parsed['sessionId']
            . pack('nC', $chosenSuite, 0)
            . pack('n', strlen($shExts)) . $shExts;
        $shMsg = "\x02" . substr(pack('N', strlen($shBody)), 1, 3) . $shBody;

        // 6. TLS 1.3 Key Schedule (RFC 8446 §7.1)
        $transcript = $parsed['rawHandshake'] . $shMsg;
        $earlySecret = self::hkdfExtract($this->hashAlgo, '', '');
        $derivedEarly = self::deriveSecret($this->hashAlgo, $earlySecret, 'derived', '');
        $handshakeSecret = self::hkdfExtract($this->hashAlgo, $derivedEarly, $tlsShared);

        $cHsTraffic = self::deriveSecret($this->hashAlgo, $handshakeSecret, 'c hs traffic', $transcript);
        $sHsTraffic = self::deriveSecret($this->hashAlgo, $handshakeSecret, 's hs traffic', $transcript);

        $this->clientHsKey = self::hkdfExpandLabel($this->hashAlgo, $cHsTraffic, 'key', '', $this->keyLen);
        $this->clientHsIv = self::hkdfExpandLabel($this->hashAlgo, $cHsTraffic, 'iv', '', 12);
        $sHsKey = self::hkdfExpandLabel($this->hashAlgo, $sHsTraffic, 'key', '', $this->keyLen);
        $sHsIv = self::hkdfExpandLabel($this->hashAlgo, $sHsTraffic, 'iv', '', 12);
        $sHsSeq = 0;

        // 7. EncryptedExtensions, REALITY HMAC-signed Ed25519 Certificate, CertificateVerify, Finished
        $eeExts = $parsed['sni'] !== '' ? pack('nn', 0x0000, 0) : '';
        if (in_array('h2', $parsed['alpn'], true)) {
            $eeExts .= pack('nnnC', 0x0010, 5, 3, 2) . 'h2';
        } elseif (in_array('http/1.1', $parsed['alpn'], true)) {
            $eeExts .= pack('nnnC', 0x0010, 11, 9, 8) . 'http/1.1';
        }
        $eeBody = pack('n', strlen($eeExts)) . $eeExts;
        $eeMsg = "\x08" . substr(pack('N', strlen($eeBody)), 1, 3) . $eeBody;
        $transcript .= $eeMsg;

        [$edKey, $edPubRaw] = self::tempEd25519();
        $certDer = self::buildRealityCertificate($edPubRaw, $authKey);
        $certEntry = substr(pack('N', strlen($certDer)), 1, 3) . $certDer . "\x00\x00";
        $certBody = "\x00" . substr(pack('N', strlen($certEntry)), 1, 3) . $certEntry;
        $certMsg = "\x0b" . substr(pack('N', strlen($certBody)), 1, 3) . $certBody;
        $transcript .= $certMsg;

        $toSign = str_repeat("\x20", 64) . "TLS 1.3, server CertificateVerify\x00" . hash($this->hashAlgo, $transcript, true);
        $cvSig = '';
        openssl_sign($toSign, $cvSig, $edKey, 0);
        // Ed25519 SignatureScheme = 0x0807
        $cvBody = pack('nn', 0x0807, strlen($cvSig)) . $cvSig;
        $cvMsg = "\x0f" . substr(pack('N', strlen($cvBody)), 1, 3) . $cvBody;
        $transcript .= $cvMsg;

        $sFinKey = self::hkdfExpandLabel($this->hashAlgo, $sHsTraffic, 'finished', '', $this->hashLen);
        $sFinVerify = hash_hmac($this->hashAlgo, hash($this->hashAlgo, $transcript, true), $sFinKey, true);
        $sFinMsg = "\x14" . substr(pack('N', strlen($sFinVerify)), 1, 3) . $sFinVerify;
        $transcript .= $sFinMsg;

        // 8. Derive Application Traffic Secrets & Expected Client Finished
        $derivedHs = self::deriveSecret($this->hashAlgo, $handshakeSecret, 'derived', '');
        $masterSecret = self::hkdfExtract($this->hashAlgo, $derivedHs, '');
        $cAppTraffic = self::deriveSecret($this->hashAlgo, $masterSecret, 'c ap traffic', $transcript);
        $sAppTraffic = self::deriveSecret($this->hashAlgo, $masterSecret, 's ap traffic', $transcript);

        $this->clientAppKey = self::hkdfExpandLabel($this->hashAlgo, $cAppTraffic, 'key', '', $this->keyLen);
        $this->clientAppIv = self::hkdfExpandLabel($this->hashAlgo, $cAppTraffic, 'iv', '', 12);
        $this->serverAppKey = self::hkdfExpandLabel($this->hashAlgo, $sAppTraffic, 'key', '', $this->keyLen);
        $this->serverAppIv = self::hkdfExpandLabel($this->hashAlgo, $sAppTraffic, 'iv', '', 12);

        $cFinKey = self::hkdfExpandLabel($this->hashAlgo, $cHsTraffic, 'finished', '', $this->hashLen);
        $this->expectedClientFinished = hash_hmac($this->hashAlgo, hash($this->hashAlgo, $transcript, true), $cFinKey, true);

        // 9. Send ServerHello + ChangeCipherSpec + encrypted handshake records
        $wire = "\x16\x03\x03" . pack('n', strlen($shMsg)) . $shMsg
            . "\x14\x03\x03\x00\x01\x01"
            . self::encryptRecord($this->cipherMethod, $sHsKey, $sHsIv, $sHsSeq, $eeMsg, 0x16)
            . self::encryptRecord($this->cipherMethod, $sHsKey, $sHsIv, $sHsSeq, $certMsg, 0x16)
            . self::encryptRecord($this->cipherMethod, $sHsKey, $sHsIv, $sHsSeq, $cvMsg, 0x16)
            . self::encryptRecord($this->cipherMethod, $sHsKey, $sHsIv, $sHsSeq, $sFinMsg, 0x16);

        $this->state = self::STATE_CLIENT_FINISHED;
        $connection->sendRaw($wire);

        return null;
    }

    /**
     * Build a client TLS 1.3 `ClientHello` record authenticated with REALITY's `SessionId` AEAD
     * (used by tests and client-side verification).
     *
     * @return array{record: string, rawHandshake: string, authKey: string, clientEphPriv: string, clientEphPub: string, sessionId: string}
     */
    public static function buildClientHello(
        string $serverPublicKeyRaw,
        string $sni = 'www.apple.com',
        string $shortIdRaw = "\x00\x00\x00\x00\x00\x00\x00\x00",
        array $version = [1, 8, 4],
        ?int $timestamp = null,
    ): array {
        $eph = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_X25519]);
        if ($eph === false) {
            throw new RuntimeException('Failed to generate client X25519 key');
        }
        $d = openssl_pkey_get_details($eph);
        $clientPriv = (string) $d['x25519']['priv_key'];
        $clientPub = (string) $d['x25519']['pub_key'];

        $random = random_bytes(32);
        $shared = self::x25519Ecdh($clientPriv, $serverPublicKeyRaw);
        if ($shared === false) {
            throw new RuntimeException('Failed to derive REALITY ECDH shared key');
        }
        $prk = self::hkdfExtract('sha256', substr($random, 0, 20), $shared);
        $authKey = self::hkdfExpand('sha256', $prk, 'REALITY', 32);

        $plainSid = chr($version[0] ?? 1) . chr($version[1] ?? 8) . chr($version[2] ?? 4) . "\x00"
            . pack('N', $timestamp ?? time())
            . substr(str_pad($shortIdRaw, 8, "\x00"), 0, 8);

        // Extensions: server_name (0x0000), supported_versions (0x002b), signature_algorithms (0x000d),
        // supported_groups (0x000a), key_share (0x0033)
        $sniHost = pack('Cn', 0, strlen($sni)) . $sni;
        $extSni = pack('nnn', 0x0000, strlen($sniHost) + 2, strlen($sniHost)) . $sniHost;
        $extVers = pack('nnCnn', 0x002B, 5, 4, 0x0304, 0x0303);
        $extSigs = pack('nnnnn', 0x000D, 6, 4, 0x0807, 0x0403);
        $extGroups = pack('nnnn', 0x000A, 4, 2, self::GROUP_X25519);
        $ksEntry = pack('nn', self::GROUP_X25519, 32) . $clientPub;
        $extKs = pack('nnn', 0x0033, strlen($ksEntry) + 2, strlen($ksEntry)) . $ksEntry;
        $exts = $extSni . $extVers . $extSigs . $extGroups . $extKs;

        $ciphers = pack('nnnn', 6, self::TLS_AES_128_GCM_SHA256, self::TLS_CHACHA20_POLY1305_SHA256, self::TLS_AES_256_GCM_SHA384);
        $zeroSid = str_repeat("\x00", 32);
        $bodyZero = "\x03\x03" . $random . "\x20" . $zeroSid . $ciphers . "\x01\x00" . pack('n', strlen($exts)) . $exts;
        $hsZero = "\x01" . substr(pack('N', strlen($bodyZero)), 1, 3) . $bodyZero;

        $tag = '';
        $ct = openssl_encrypt($plainSid, 'aes-256-gcm', $authKey, OPENSSL_RAW_DATA, substr($random, 20, 12), $tag, $hsZero, 16);
        if ($ct === false) {
            throw new RuntimeException('Failed to encrypt REALITY SessionId');
        }
        $sessionId = $ct . $tag;
        $hs = substr_replace($hsZero, $sessionId, 39, 32);

        return [
            'record' => "\x16\x03\x01" . pack('n', strlen($hs)) . $hs,
            'rawHandshake' => $hs,
            'authKey' => $authKey,
            'clientEphPriv' => $clientPriv,
            'clientEphPub' => $clientPub,
            'sessionId' => $sessionId,
        ];
    }

    /**
     * Parse a TLS ClientHello record.
     *
     * @return array{
     *     rawHandshake: string,
     *     rawHandshakeZeroedSid: string,
     *     random: string,
     *     sessionId: string,
     *     cipherSuites: list<int>,
     *     sni: string,
     *     alpn: list<string>,
     *     versions: list<int>,
     *     x25519Share: string|null
     * }|null
     */
    public static function parseClientHelloRecord(string $record): ?array
    {
        if (strlen($record) < 44 || $record[0] !== "\x16") {
            return null;
        }
        $recLen = unpack('n', substr($record, 3, 2))[1];
        if (strlen($record) < 5 + $recLen) {
            return null;
        }
        $hs = substr($record, 5, $recLen);
        if ($hs[0] !== "\x01") {
            return null;
        }
        $hsLen = unpack('N', "\x00" . substr($hs, 1, 3))[1];
        if (strlen($hs) < 4 + $hsLen || $hsLen < 38) {
            return null;
        }
        $hs = substr($hs, 0, 4 + $hsLen);

        $random = substr($hs, 6, 32);
        $sidLen = ord($hs[38]);
        $at = 39 + $sidLen;
        if (strlen($hs) < $at + 2) {
            return null;
        }
        $sessionId = substr($hs, 39, $sidLen);
        $hsZero = $sidLen === 32 ? substr_replace($hs, str_repeat("\x00", 32), 39, 32) : $hs;

        $csLen = unpack('n', substr($hs, $at, 2))[1];
        $at += 2;
        if (strlen($hs) < $at + $csLen + 1) {
            return null;
        }
        $cipherSuites = [];
        for ($i = 0; $i + 1 < $csLen; $i += 2) {
            $cipherSuites[] = unpack('n', substr($hs, $at + $i, 2))[1];
        }
        $at += $csLen;

        $compLen = ord($hs[$at]);
        $at += 1 + $compLen;
        if (strlen($hs) < $at + 2) {
            return null;
        }
        $extTotal = unpack('n', substr($hs, $at, 2))[1];
        $at += 2;
        $extEnd = min(strlen($hs), $at + $extTotal);

        $sni = '';
        $alpn = [];
        $versions = [];
        $x25519Share = null;
        $mlkemX25519Share = null;

        while ($at + 4 <= $extEnd) {
            $extType = unpack('n', substr($hs, $at, 2))[1];
            $extLen = unpack('n', substr($hs, $at + 2, 2))[1];
            $at += 4;
            if ($at + $extLen > $extEnd) {
                break;
            }
            $extData = substr($hs, $at, $extLen);
            $at += $extLen;

            if ($extType === 0x0000 && strlen($extData) >= 5) {
                // server_name
                $nameType = ord($extData[2]);
                $nameLen = unpack('n', substr($extData, 3, 2))[1];
                if ($nameType === 0 && strlen($extData) >= 5 + $nameLen) {
                    $sni = substr($extData, 5, $nameLen);
                }
            } elseif ($extType === 0x0010 && strlen($extData) >= 3) {
                // ALPN
                $pAt = 2;
                while ($pAt < strlen($extData)) {
                    $pLen = ord($extData[$pAt]);
                    $pAt++;
                    if ($pAt + $pLen <= strlen($extData)) {
                        $alpn[] = substr($extData, $pAt, $pLen);
                    }
                    $pAt += $pLen;
                }
            } elseif ($extType === 0x002B && strlen($extData) >= 3) {
                // supported_versions
                $vLen = ord($extData[0]);
                for ($i = 1; $i + 1 <= min(strlen($extData), 1 + $vLen); $i += 2) {
                    $versions[] = unpack('n', substr($extData, $i, 2))[1];
                }
            } elseif ($extType === 0x0033 && strlen($extData) >= 2) {
                // key_share
                $ksLen = unpack('n', substr($extData, 0, 2))[1];
                $kAt = 2;
                $kEnd = min(strlen($extData), 2 + $ksLen);
                while ($kAt + 4 <= $kEnd) {
                    $group = unpack('n', substr($extData, $kAt, 2))[1];
                    $kLen = unpack('n', substr($extData, $kAt + 2, 2))[1];
                    $kAt += 4;
                    if ($kAt + $kLen > $kEnd) {
                        break;
                    }
                    $kBytes = substr($extData, $kAt, $kLen);
                    $kAt += $kLen;
                    if ($group === self::GROUP_X25519 && $kLen === 32 && $x25519Share === null) {
                        $x25519Share = $kBytes;
                    } elseif ($group === self::GROUP_X25519_MLKEM768 && $kLen === 1184 + 32 && $mlkemX25519Share === null) {
                        $mlkemX25519Share = substr($kBytes, 1184, 32);
                    }
                }
            }
        }

        return [
            'rawHandshake' => $hs,
            'rawHandshakeZeroedSid' => $hsZero,
            'random' => $random,
            'sessionId' => $sessionId,
            'cipherSuites' => $cipherSuites,
            'sni' => $sni,
            'alpn' => $alpn,
            'versions' => $versions,
            'x25519Share' => $x25519Share ?? $mlkemX25519Share,
        ];
    }

    /**
     * Build the DER-encoded X.509 certificate for REALITY: an Ed25519 public key whose 64-byte
     * certificate signature is `HMAC-SHA512(key: AuthKey, data: ed25519PublicKey)`.
     */
    public static function buildRealityCertificate(string $ed25519PubRaw, string $authKey): string
    {
        $algId = "\x30\x05\x06\x03\x2b\x65\x70"; // OID 1.3.101.112 (Ed25519)
        $tbs = self::asn1Seq(
            "\x02\x01\x00" // serialNumber 0
            . $algId
            . "\x30\x00" // empty issuer
            . self::asn1Seq("\x17\x0d700101000000Z\x17\x0d700101000000Z")
            . "\x30\x00" // empty subject
            . self::asn1Seq($algId . self::asn1BitStr($ed25519PubRaw))
        );
        $hmacSig = hash_hmac('sha512', $ed25519PubRaw, $authKey, true);

        return self::asn1Seq($tbs . $algId . self::asn1BitStr($hmacSig));
    }

    /**
     * @return array{0: OpenSSLAsymmetricKey, 1: string}
     */
    private static function tempEd25519(): array
    {
        if (self::$ed25519Key === null) {
            $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_ED25519]);
            if ($key === false) {
                throw new RuntimeException('Failed to generate temporary Ed25519 key for REALITY');
            }
            $d = openssl_pkey_get_details($key);
            self::$ed25519Key = $key;
            self::$ed25519PubRaw = (string) $d['ed25519']['pub_key'];
        }

        return [self::$ed25519Key, self::$ed25519PubRaw];
    }

    private static function loadPrivateKey(string $privateKeyRaw): OpenSSLAsymmetricKey
    {
        $pem = "-----BEGIN PRIVATE KEY-----\n"
            . base64_encode(self::X25519_PKCS8_PREFIX . $privateKeyRaw)
            . "\n-----END PRIVATE KEY-----\n";
        $key = openssl_pkey_get_private($pem);
        if ($key === false) {
            throw new RuntimeException('Failed to load X25519 private key');
        }

        return $key;
    }

    private static function asn1Len(int $len): string
    {
        if ($len < 0x80) {
            return chr($len);
        }
        $b = ltrim(pack('N', $len), "\x00");

        return chr(0x80 | strlen($b)) . $b;
    }

    private static function asn1Seq(string $body): string
    {
        return "\x30" . self::asn1Len(strlen($body)) . $body;
    }

    private static function asn1BitStr(string $body): string
    {
        return "\x03" . self::asn1Len(strlen($body) + 1) . "\x00" . $body;
    }
}
