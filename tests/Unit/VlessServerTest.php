<?php

declare(strict_types=1);

namespace PigVless\Test\Unit;

use PHPUnit\Framework\TestCase;
use Pig\Async\Async;
use Pig\Async\Loop;
use Pig\Async\Socket;
use PigVless\VlessServer;
use RuntimeException;

/**
 * A phone, a VLESS inbound, and somewhere to go — all three on loopback.
 */
final class VlessServerTest extends TestCase
{
    private const string UUID = '7a3f1c2e-9b4d-4e6f-8a1b-2c3d4e5f6a7b';

    private VlessServer $server;

    /** @var resource */
    private $echo;

    private ?string $echoWatcher = null;

    private int $echoPort;

    /** @var list<resource> */
    private array $echoClients = [];

    #[\Override]
    protected function setUp(): void
    {
        Loop::reset();

        $this->echoPort = self::freePort();
        $this->echo = stream_socket_server("tcp://127.0.0.1:{$this->echoPort}") ?: throw new RuntimeException('no echo');
        stream_set_blocking($this->echo, false);
        $this->echoWatcher = Loop::get()->onReadable($this->echo, function (): void {
            set_error_handler(static fn (): bool => true);
            try {
                $client = stream_socket_accept($this->echo, 0);
            } finally {
                restore_error_handler();
            }

            if ($client === false) {
                return;
            }

            stream_set_blocking($client, false);
            $this->echoClients[] = [
                'socket' => $client,
                'watcher' => Loop::get()->onReadable($client, static function () use ($client): void {
                    $data = fread($client, 65536);

                    if ($data !== false && $data !== '') {
                        fwrite($client, strtoupper($data));
                    }
                }),
            ];
        });

        $this->server = new VlessServer('127.0.0.1', self::freePort(), self::UUID);
        $this->server->start();
    }

    #[\Override]
    protected function tearDown(): void
    {
        $this->server->stop();

        foreach ($this->echoClients as $ec) {
            Loop::get()->cancel($ec['watcher']);
            if (is_resource($ec['socket'])) {
                fclose($ec['socket']);
            }
        }
        $this->echoClients = [];

        if ($this->echoWatcher !== null) {
            Loop::get()->cancel($this->echoWatcher);
        }

        fclose($this->echo);
    }

    public function testATcpRequestIsAnsweredWithTheHeaderAndThenRelayed(): void
    {
        $reply = $this->through(self::header(self::UUID, VlessServer::CMD_TCP, '127.0.0.1', $this->echoPort) . 'hello');

        $this->assertSame("\x00\x00", substr($reply, 0, 2), 'version 0, no addons');
        $this->assertSame('HELLO', substr($reply, 2));
    }

    public function testADomainAddressAndAPayloadSentLaterBothWork(): void
    {
        $reply = $this->through(self::header(self::UUID, VlessServer::CMD_TCP, 'localhost', $this->echoPort), then: 'later');

        $this->assertSame("\x00\x00LATER", $reply);
    }

    public function testAHeaderSplitAcrossTwoWritesIsStillOneHeader(): void
    {
        $header = self::header(self::UUID, VlessServer::CMD_TCP, '127.0.0.1', $this->echoPort);
        $reply = $this->through(substr($header, 0, 10), then: substr($header, 10) . 'split');

        $this->assertSame("\x00\x00SPLIT", $reply);
    }

    public function testTheWrongUuidIsClosedWithoutAWord(): void
    {
        $reply = $this->through(self::header('00000000-0000-4000-8000-000000000000', VlessServer::CMD_TCP, '127.0.0.1', $this->echoPort) . 'hello');

        $this->assertSame('', $reply);
    }

    public function testUdpIsRefused(): void
    {
        $this->assertSame('', $this->through(self::header(self::UUID, VlessServer::CMD_UDP, '127.0.0.1', $this->echoPort) . 'x'));
    }

    public function testSomethingThatIsNotVlessIsClosed(): void
    {
        $this->assertSame('', $this->through("GET / HTTP/1.1\r\nHost: x\r\n\r\n"));
    }

    public function testTheHeaderParserKnowsAllThreeAddressTypes(): void
    {
        $v4 = VlessServer::parse(self::header(self::UUID, 1, '10.0.0.1', 443) . 'p');
        $this->assertSame(['10.0.0.1', 443, 'p'], [$v4['host'], $v4['port'], $v4['payload']]);

        $v6 = VlessServer::parse(self::header(self::UUID, 1, '2001:db8::1', 53));
        $this->assertSame('2001:db8::1', $v6['host']);

        $name = VlessServer::parse(self::header(self::UUID, 1, 'example.com', 80));
        $this->assertSame('example.com', $name['host']);

        $this->assertNull(VlessServer::parse(substr(self::header(self::UUID, 1, 'example.com', 80), 0, 20)), 'a prefix is not yet a header');
        $this->assertFalse(VlessServer::parse("\x01" . str_repeat('x', 40)), 'version 1 is not VLESS');
    }

    public function testTheShareLinkNamesTheKeyThePortAndThePlainTransport(): void
    {
        $link = $this->server->shareLink('192.168.1.2', 'home mac');

        $this->assertSame('vless://' . self::UUID . "@192.168.1.2:{$this->server->port}?encryption=none&security=none&type=tcp#home%20mac", $link);
    }

    public function testAWebSocketRequestUpgradesAndRelaysBinaryFrames(): void
    {
        $wsServer = new VlessServer('127.0.0.1', self::freePort(), self::UUID, wsPath: 'vless');
        $wsServer->start();

        try {
            $this->assertSame('/vless', $wsServer->wsPath);
            $this->assertSame(
                'vless://' . self::UUID . "@example.com:{$wsServer->port}?encryption=none&security=none&type=ws&path=%2Fvless#ws",
                $wsServer->shareLink('example.com', 'ws'),
            );

            $frame = self::maskedBinaryFrame(self::header(self::UUID, VlessServer::CMD_TCP, '127.0.0.1', $this->echoPort) . 'ws-hello');
            $reply = $this->throughWs($wsServer->port, '/vless', $frame);

            $this->assertSame("\x00\x00WS-HELLO", $reply);
        } finally {
            $wsServer->stop();
        }
    }

    public function testWebSocketEarlyDataInSecWebSocketProtocolIsRelayed(): void
    {
        $wsServer = new VlessServer('127.0.0.1', self::freePort(), self::UUID, wsPath: '/vless');
        $wsServer->start();

        try {
            $early = rtrim(strtr(base64_encode(self::header(self::UUID, VlessServer::CMD_TCP, '127.0.0.1', $this->echoPort) . 'early'), '+/', '-_'), '=');
            $reply = $this->throughWs($wsServer->port, '/vless', '', earlyProtocol: $early);

            $this->assertSame("\x00\x00EARLY", $reply);
        } finally {
            $wsServer->stop();
        }
    }

    public function testWebSocketRefusesTheWrongPath(): void
    {
        $wsServer = new VlessServer('127.0.0.1', self::freePort(), self::UUID, wsPath: '/vless');
        $wsServer->start();

        try {
            $frame = self::maskedBinaryFrame(self::header(self::UUID, VlessServer::CMD_TCP, '127.0.0.1', $this->echoPort) . 'nope');
            $this->assertSame('', $this->throughWs($wsServer->port, '/wrong', $frame));
        } finally {
            $wsServer->stop();
        }
    }

    public function testRealityShareLinkAndKeygenFormat(): void
    {
        $pair = \PigVless\Reality::generateKeyPair();
        $this->assertSame(32, strlen(\PigVless\Reality::decodeKey($pair['privateKey'])));
        $this->assertSame(
            $pair['publicKey'],
            \PigVless\Reality::base64UrlEncode(\PigVless\Reality::publicKeyFromPrivate(\PigVless\Reality::decodeKey($pair['privateKey']))),
        );

        $rServer = new VlessServer('127.0.0.1', self::freePort(), self::UUID, reality: [
            'privateKey' => $pair['privateKey'],
            'dest' => "127.0.0.1:{$this->echoPort}",
            'serverNames' => ['www.apple.com'],
            'shortIds' => ['a1b2c3d4'],
            'fingerprint' => 'chrome',
        ]);

        $this->assertTrue($rServer->isReality());
        $link = $rServer->shareLink('203.0.113.10', 'reality-node');
        $this->assertSame(
            'vless://' . self::UUID . "@203.0.113.10:{$rServer->port}?encryption=none&security=reality&type=tcp&flow=xtls-rprx-vision&sni=www.apple.com&fp=chrome&pbk={$pair['publicKey']}&sid=a1b2c3d4#reality-node",
            $link,
        );
    }

    public function testRealityUnauthorizedProbeFallsBackTransparentlyToDest(): void
    {
        $pair = \PigVless\Reality::generateKeyPair();
        $rServer = new VlessServer('127.0.0.1', self::freePort(), self::UUID, reality: [
            'privateKey' => $pair['privateKey'],
            'dest' => "127.0.0.1:{$this->echoPort}",
            'serverNames' => ['www.apple.com'],
            'shortIds' => ['a1b2c3d4'],
        ]);
        $rServer->start();

        try {
            // 1. Plain HTTP probe (not TLS) -> forwarded to dest (echoes uppercase)
            $replyHttp = Async::run(function () use ($rServer): string {
                $socket = Socket::connect('127.0.0.1', $rServer->port, timeout: 2.0);
                $socket->write('probe-fallback', 2.0);
                $got = (string) $socket->read(65536, 1.0);
                $socket->close();

                return $got;
            });
            $this->assertSame('PROBE-FALLBACK', $replyHttp);

            // 2. TLS 1.3 ClientHello with wrong shortId -> forwarded raw to dest
            $badHello = \PigVless\Reality::buildClientHello(
                \PigVless\Reality::decodeKey($pair['publicKey']),
                'www.apple.com',
                \PigVless\Reality::decodeShortId('deadbeef'),
            );
            $replyBadSid = Async::run(function () use ($rServer, $badHello): string {
                $socket = Socket::connect('127.0.0.1', $rServer->port, timeout: 2.0);
                $socket->write($badHello['record'], 2.0);
                $got = (string) $socket->read(65536, 1.0);
                $socket->close();

                return $got;
            });
            $this->assertSame(strtoupper($badHello['record']), $replyBadSid);
        } finally {
            $rServer->stop();
        }
    }

    public function testRealityHandshakeHmacCertAndVisionZeroCopyDirectSplice(): void
    {
        $pair = \PigVless\Reality::generateKeyPair();
        $pubRaw = \PigVless\Reality::decodeKey($pair['publicKey']);
        $sidRaw = \PigVless\Reality::decodeShortId('a1b2c3d4');

        $rServer = new VlessServer('127.0.0.1', self::freePort(), self::UUID, reality: [
            'privateKey' => $pair['privateKey'],
            'dest' => "127.0.0.1:{$this->echoPort}",
            'serverNames' => ['www.apple.com'],
            'shortIds' => ['a1b2c3d4'],
        ]);
        $rServer->start();

        try {
            $ch = \PigVless\Reality::buildClientHello($pubRaw, 'www.apple.com', $sidRaw);

            Async::run(function () use ($rServer, $ch): void {
                $socket = Socket::connect('127.0.0.1', $rServer->port, timeout: 2.0);
                $socket->write($ch['record'], 2.0);

                // Read ServerHello + ChangeCipherSpec + 4 encrypted handshake records
                $buf = '';
                $records = [];
                while (count($records) < 6) {
                    $chunk = $socket->read(65536, 2.0);
                    if ($chunk === null || $chunk === '') {
                        break;
                    }
                    $buf .= $chunk;
                    while (strlen($buf) >= 5) {
                        $rLen = unpack('n', substr($buf, 3, 2))[1];
                        if (strlen($buf) < 5 + $rLen) {
                            break;
                        }
                        $records[] = substr($buf, 0, 5 + $rLen);
                        $buf = substr($buf, 5 + $rLen);
                    }
                }

                $this->assertCount(6, $records, 'ServerHello + CCS + EE + Cert + CV + Finished');
                $shRec = $records[0];
                $this->assertSame("\x16\x03\x03", substr($shRec, 0, 3));
                $shMsg = substr($shRec, 5);
                // Extract server's ephemeral X25519 public key (last 32 bytes of ServerHello)
                $serverEphPub = substr($shMsg, -32);
                $tlsShared = \PigVless\Reality::x25519Ecdh($ch['clientEphPriv'], $serverEphPub);
                $this->assertNotFalse($tlsShared);

                $transcript = $ch['rawHandshake'] . $shMsg;
                $early = \PigVless\Reality::hkdfExtract('sha256', '', '');
                $derivedEarly = \PigVless\Reality::deriveSecret('sha256', $early, 'derived', '');
                $hsSecret = \PigVless\Reality::hkdfExtract('sha256', $derivedEarly, $tlsShared);

                $cHsTraffic = \PigVless\Reality::deriveSecret('sha256', $hsSecret, 'c hs traffic', $transcript);
                $sHsTraffic = \PigVless\Reality::deriveSecret('sha256', $hsSecret, 's hs traffic', $transcript);

                $cHsKey = \PigVless\Reality::hkdfExpandLabel('sha256', $cHsTraffic, 'key', '', 16);
                $cHsIv = \PigVless\Reality::hkdfExpandLabel('sha256', $cHsTraffic, 'iv', '', 12);
                $sHsKey = \PigVless\Reality::hkdfExpandLabel('sha256', $sHsTraffic, 'key', '', 16);
                $sHsIv = \PigVless\Reality::hkdfExpandLabel('sha256', $sHsTraffic, 'iv', '', 12);
                $sHsSeq = 0;

                // Decrypt EncryptedExtensions, Certificate, CertificateVerify, Finished
                $ee = \PigVless\Reality::decryptRecord('aes-128-gcm', $sHsKey, $sHsIv, $sHsSeq, $records[2]);
                $cert = \PigVless\Reality::decryptRecord('aes-128-gcm', $sHsKey, $sHsIv, $sHsSeq, $records[3]);
                $cv = \PigVless\Reality::decryptRecord('aes-128-gcm', $sHsKey, $sHsIv, $sHsSeq, $records[4]);
                $fin = \PigVless\Reality::decryptRecord('aes-128-gcm', $sHsKey, $sHsIv, $sHsSeq, $records[5]);

                $this->assertNotFalse($ee);
                $this->assertNotFalse($cert);
                $this->assertNotFalse($cv);
                $this->assertNotFalse($fin);

                // Verify REALITY temporary Ed25519 certificate HMAC-SHA512 signature!
                $certDer = substr($cert['content'], 11, -2);
                $edPubInCert = substr($certDer, -106, 32);
                $hmacInCert = substr($certDer, -64);
                $expectedHmac = hash_hmac('sha512', $edPubInCert, $ch['authKey'], true);
                $this->assertSame(bin2hex($expectedHmac), bin2hex($hmacInCert), 'REALITY Ed25519 certificate carries HMAC-SHA512(authKey, ed25519Pub)');

                $transcript .= $ee['content'] . $cert['content'] . $cv['content'] . $fin['content'];

                $derivedHs = \PigVless\Reality::deriveSecret('sha256', $hsSecret, 'derived', '');
                $master = \PigVless\Reality::hkdfExtract('sha256', $derivedHs, '');
                $cAppTraffic = \PigVless\Reality::deriveSecret('sha256', $master, 'c ap traffic', $transcript);
                $sAppTraffic = \PigVless\Reality::deriveSecret('sha256', $master, 's ap traffic', $transcript);

                $cAppKey = \PigVless\Reality::hkdfExpandLabel('sha256', $cAppTraffic, 'key', '', 16);
                $cAppIv = \PigVless\Reality::hkdfExpandLabel('sha256', $cAppTraffic, 'iv', '', 12);
                $sAppKey = \PigVless\Reality::hkdfExpandLabel('sha256', $sAppTraffic, 'key', '', 16);
                $sAppIv = \PigVless\Reality::hkdfExpandLabel('sha256', $sAppTraffic, 'iv', '', 12);

                // Send Client Finished
                $cFinKey = \PigVless\Reality::hkdfExpandLabel('sha256', $cHsTraffic, 'finished', '', 32);
                $cFinVerify = hash_hmac('sha256', hash('sha256', $transcript, true), $cFinKey, true);
                $cFinMsg = "\x14" . substr(pack('N', strlen($cFinVerify)), 1, 3) . $cFinVerify;
                $cHsSeq = 0;
                $socket->write(\PigVless\Reality::encryptRecord('aes-128-gcm', $cHsKey, $cHsIv, $cHsSeq, $cFinMsg, 0x16), 2.0);

                // Send VLESS request with flow=xtls-rprx-vision + Vision-padded block switching to CMD_DIRECT (2)
                $uuidRaw = hex2bin(str_replace('-', '', self::UUID));
                $vlessReq = self::header(self::UUID, VlessServer::CMD_TCP, '127.0.0.1', $this->echoPort, \PigVless\Vision::FLOW);
                $clientVision = new \PigVless\Vision($uuidRaw);
                $visionBlock = $clientVision->padBlock('vision-payload', \PigVless\Vision::CMD_DIRECT, true, 32);

                $cAppSeq = 0;
                $socket->write(\PigVless\Reality::encryptRecord('aes-128-gcm', $cAppKey, $cAppIv, $cAppSeq, $vlessReq . $visionBlock, 0x17), 2.0);

                // Read encrypted outer TLS 1.3 response containing VLESS response header + Vision-padded echo reply
                $replyRec = (string) $socket->read(65536, 2.0);
                $sAppSeq = 0;
                $decReply = \PigVless\Reality::decryptRecord('aes-128-gcm', $sAppKey, $sAppIv, $sAppSeq, $replyRec);
                $this->assertNotFalse($decReply);
                $this->assertSame("\x00\x00", substr($decReply['content'], 0, 2));
                $unpadded = $clientVision->unwrapUplink(substr($decReply['content'], 2));
                $this->assertSame('VISION-PAYLOAD', $unpadded['data']);

                // Because uplink sent CMD_DIRECT (2), subsequent uplink bytes go RAW without outer TLS encryption!
                $socket->write('raw-splice-after-direct', 2.0);
                $replyRec2 = (string) $socket->read(65536, 2.0);
                $decReply2 = \PigVless\Reality::decryptRecord('aes-128-gcm', $sAppKey, $sAppIv, $sAppSeq, $replyRec2);
                $this->assertNotFalse($decReply2);
                $unpadded2 = $clientVision->unwrapUplink($decReply2['content']);
                $this->assertSame('RAW-SPLICE-AFTER-DIRECT', $unpadded2['data']);

                $socket->close();
            });
        } finally {
            $rServer->stop();
        }
    }

    public function testVisionDownlinkFiltersInnerTls13AndSwitchesToDirectSplice(): void
    {
        $pair = \PigVless\Reality::generateKeyPair();
        $pubRaw = \PigVless\Reality::decodeKey($pair['publicKey']);
        $sidRaw = \PigVless\Reality::decodeShortId('a1b2c3d4');

        // Mock an inner TLS 1.3 destination server that replies with a TLS 1.3 ServerHello + ApplicationData
        $innerPort = self::freePort();
        $innerServer = stream_socket_server("tcp://127.0.0.1:{$innerPort}") ?: throw new RuntimeException('no inner tls');
        stream_set_blocking($innerServer, false);
        $innerClients = [];
        $innerWatcher = Loop::get()->onReadable($innerServer, function () use ($innerServer, &$innerClients): void {
            set_error_handler(static fn (): bool => true);
            try {
                $c = stream_socket_accept($innerServer, 0);
            } finally {
                restore_error_handler();
            }
            if ($c === false) {
                return;
            }
            stream_set_blocking($c, false);
            $w = null;
            $w = Loop::get()->onReadable($c, static function () use ($c): void {
                $in = fread($c, 65536);
                if ($in === false || $in === '') {
                    return;
                }
                // Build a realistic inner TLS 1.3 ServerHello record (>= 79 bytes, cipher 0x1301, supported_versions 0x002b 0x0002 0x0304)
                $shBody = "\x03\x03" . str_repeat("\x11", 32) . "\x20" . str_repeat("\x22", 32) . "\x13\x01\x00"
                    . "\x00\x06\x00\x2b\x00\x02\x03\x04";
                $shMsg = "\x02" . substr(pack('N', strlen($shBody)), 1, 3) . $shBody;
                $shRecord = "\x16\x03\x03" . pack('n', strlen($shMsg)) . $shMsg;
                fwrite($c, $shRecord);
                fflush($c);
            });
            $innerClients[] = ['socket' => $c, 'watcher' => $w];
        });

        $rServer = new VlessServer('127.0.0.1', self::freePort(), self::UUID, reality: [
            'privateKey' => $pair['privateKey'],
            'dest' => "127.0.0.1:{$this->echoPort}",
            'serverNames' => ['www.apple.com'],
            'shortIds' => ['a1b2c3d4'],
        ]);
        $rServer->start();

        try {
            $ch = \PigVless\Reality::buildClientHello($pubRaw, 'www.apple.com', $sidRaw);

            Async::run(function () use ($rServer, $innerPort, $ch, &$innerClients): void {
                $socket = Socket::connect('127.0.0.1', $rServer->port, timeout: 2.0);
                $socket->write($ch['record'], 2.0);

                $buf = '';
                $records = [];
                while (count($records) < 6) {
                    $chunk = $socket->read(65536, 2.0);
                    if ($chunk === null || $chunk === '') {
                        break;
                    }
                    $buf .= $chunk;
                    while (strlen($buf) >= 5) {
                        $rLen = unpack('n', substr($buf, 3, 2))[1];
                        if (strlen($buf) < 5 + $rLen) {
                            break;
                        }
                        $records[] = substr($buf, 0, 5 + $rLen);
                        $buf = substr($buf, 5 + $rLen);
                    }
                }

                $shMsg = substr($records[0], 5);
                $serverEphPub = substr($shMsg, -32);
                $tlsShared = \PigVless\Reality::x25519Ecdh($ch['clientEphPriv'], $serverEphPub);
                $transcript = $ch['rawHandshake'] . $shMsg;
                $early = \PigVless\Reality::hkdfExtract('sha256', '', '');
                $hsSecret = \PigVless\Reality::hkdfExtract('sha256', \PigVless\Reality::deriveSecret('sha256', $early, 'derived', ''), $tlsShared);
                $cHsTraffic = \PigVless\Reality::deriveSecret('sha256', $hsSecret, 'c hs traffic', $transcript);
                $sHsTraffic = \PigVless\Reality::deriveSecret('sha256', $hsSecret, 's hs traffic', $transcript);
                $cHsKey = \PigVless\Reality::hkdfExpandLabel('sha256', $cHsTraffic, 'key', '', 16);
                $cHsIv = \PigVless\Reality::hkdfExpandLabel('sha256', $cHsTraffic, 'iv', '', 12);
                $sHsKey = \PigVless\Reality::hkdfExpandLabel('sha256', $sHsTraffic, 'key', '', 16);
                $sHsIv = \PigVless\Reality::hkdfExpandLabel('sha256', $sHsTraffic, 'iv', '', 12);
                $sHsSeq = 0;

                foreach ([2, 3, 4, 5] as $idx) {
                    $dec = \PigVless\Reality::decryptRecord('aes-128-gcm', $sHsKey, $sHsIv, $sHsSeq, $records[$idx]);
                    $transcript .= $dec['content'];
                }

                $master = \PigVless\Reality::hkdfExtract('sha256', \PigVless\Reality::deriveSecret('sha256', $hsSecret, 'derived', ''), '');
                $cAppTraffic = \PigVless\Reality::deriveSecret('sha256', $master, 'c ap traffic', $transcript);
                $sAppTraffic = \PigVless\Reality::deriveSecret('sha256', $master, 's ap traffic', $transcript);
                $cAppKey = \PigVless\Reality::hkdfExpandLabel('sha256', $cAppTraffic, 'key', '', 16);
                $cAppIv = \PigVless\Reality::hkdfExpandLabel('sha256', $cAppTraffic, 'iv', '', 12);
                $sAppKey = \PigVless\Reality::hkdfExpandLabel('sha256', $sAppTraffic, 'key', '', 16);
                $sAppIv = \PigVless\Reality::hkdfExpandLabel('sha256', $sAppTraffic, 'iv', '', 12);

                $cFinKey = \PigVless\Reality::hkdfExpandLabel('sha256', $cHsTraffic, 'finished', '', 32);
                $cFinVerify = hash_hmac('sha256', hash('sha256', $transcript, true), $cFinKey, true);
                $cFinMsg = "\x14" . substr(pack('N', strlen($cFinVerify)), 1, 3) . $cFinVerify;
                $cHsSeq = 0;
                $socket->write(\PigVless\Reality::encryptRecord('aes-128-gcm', $cHsKey, $cHsIv, $cHsSeq, $cFinMsg, 0x16), 2.0);

                // Send VLESS request + inner TLS ClientHello (0x16 0x03 0x01 0x00 0x08 0x01 ...)
                $uuidRaw = hex2bin(str_replace('-', '', self::UUID));
                $vlessReq = self::header(self::UUID, VlessServer::CMD_TCP, '127.0.0.1', $innerPort, \PigVless\Vision::FLOW);
                $clientVision = new \PigVless\Vision($uuidRaw);
                $innerCh = "\x16\x03\x01\x00\x08\x01\x00\x00\x04\x03\x03\xaa\xbb";
                $visionBlock = $clientVision->padBlock($innerCh, \PigVless\Vision::CMD_CONTINUE, true, 16);
                $cAppSeq = 0;
                $socket->write(\PigVless\Reality::encryptRecord('aes-128-gcm', $cAppKey, $cAppIv, $cAppSeq, $vlessReq . $visionBlock, 0x17), 2.0);

                // Read first downlink Vision block (contains VLESS response header + inner ServerHello)
                $sAppSeq = 0;
                $downlinkVision = new \PigVless\Vision($uuidRaw);
                $rec1 = (string) $socket->read(65536, 2.0);
                $dec1 = \PigVless\Reality::decryptRecord('aes-128-gcm', $sAppKey, $sAppIv, $sAppSeq, $rec1);
                $this->assertNotFalse($dec1);
                $this->assertSame("\x00\x00", substr($dec1['content'], 0, 2));
                $res1 = $downlinkVision->unwrapUplink(substr($dec1['content'], 2));
                $this->assertFalse($res1['switchedToDirect']);

                // Next write from inner destination: a complete inner TLS 1.3 ApplicationData record -> triggers Vision CMD_DIRECT (2) + outer directWrite!
                fwrite($innerClients[0]['socket'], "\x17\x03\x03\x00\x0cINNER-APP-01");
                $rec2 = (string) $socket->read(65536, 2.0);
                $dec2 = \PigVless\Reality::decryptRecord('aes-128-gcm', $sAppKey, $sAppIv, $sAppSeq, $rec2);
                $this->assertNotFalse($dec2);
                $res2 = $downlinkVision->unwrapUplink($dec2['content']);
                $this->assertTrue($res2['switchedToDirect'], 'Vision downlink detected inner TLS 1.3 ApplicationData and switched to CMD_DIRECT (2)');
                $this->assertSame("\x17\x03\x03\x00\x0cINNER-APP-01", $res2['data']);

                // Now that downlink switched to directWrite, the inner destination sends a second TLS record and it arrives RAW without outer TLS encryption!
                fwrite($innerClients[0]['socket'], "\x17\x03\x03\x00\x0cRAW-SPLICE-2");
                $rawDownlink = (string) $socket->read(65536, 2.0);
                $this->assertSame("\x17\x03\x03\x00\x0cRAW-SPLICE-2", $rawDownlink);

                $socket->close();
            });
        } finally {
            $rServer->stop();
            Loop::get()->cancel($innerWatcher);
            foreach ($innerClients as $ic) {
                Loop::get()->cancel($ic['watcher']);
                if (is_resource($ic['socket'])) {
                    fclose($ic['socket']);
                }
            }
            fclose($innerServer);
        }
    }

    // ---- the phone -------------------------------------------------------------------------

    private function through(string $first, string $then = ''): string
    {
        return Async::run(function () use ($first, $then): string {
            $socket = Socket::connect('127.0.0.1', $this->server->port, timeout: 2.0);
            $socket->write($first, 2.0);

            if ($then !== '') {
                Async::delay(0.05);
                $socket->write($then, 2.0);
            }

            $got = '';
            $deadline = microtime(true) + 1.0;

            while (microtime(true) < $deadline) {
                try {
                    $chunk = $socket->read(65536, 0.1);
                } catch (\Throwable) {
                    break;
                }

                if ($chunk === null) {
                    break;
                }

                $got .= $chunk;

                if (strlen($got) >= 2 && !str_ends_with($got, "\x00\x00") && strlen($got) > 2) {
                    break;
                }
            }

            $socket->close();

            return $got;
        });
    }

    private static function header(string $uuid, int $command, string $host, int $port, string $flow = ''): string
    {
        $address = match (true) {
            filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false => "\x01" . inet_pton($host),
            filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false => "\x03" . inet_pton($host),
            default => "\x02" . chr(strlen($host)) . $host,
        };
        $addons = \PigVless\Vision::encodeAddonsFlow($flow);

        return "\x00" . hex2bin(str_replace('-', '', $uuid)) . chr(strlen($addons)) . $addons . chr($command) . pack('n', $port) . $address;
    }

    private static function maskedBinaryFrame(string $payload): string
    {
        $mask = "\x12\x34\x56\x78";
        $len = strlen($payload);
        $masked = $payload ^ substr(str_repeat($mask, intdiv($len, 4) + 1), 0, $len);

        return "\x82" . chr(0x80 | $len) . $mask . $masked;
    }

    private function throughWs(int $port, string $path, string $frames, ?string $earlyProtocol = null): string
    {
        return Async::run(function () use ($port, $path, $frames, $earlyProtocol): string {
            $socket = Socket::connect('127.0.0.1', $port, timeout: 2.0);
            $request = "GET {$path} HTTP/1.1\r\n"
                . "Host: 127.0.0.1:{$port}\r\n"
                . "Upgrade: websocket\r\n"
                . "Connection: Upgrade\r\n"
                . "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                . ($earlyProtocol !== null ? "Sec-WebSocket-Protocol: {$earlyProtocol}\r\n" : '')
                . "\r\n";

            $socket->write($request . $frames, 2.0);

            $raw = '';
            $deadline = microtime(true) + 1.0;

            while (microtime(true) < $deadline) {
                try {
                    $chunk = $socket->read(65536, 0.1);
                } catch (\Throwable) {
                    break;
                }

                if ($chunk === null) {
                    break;
                }

                $raw .= $chunk;
                $headEnd = strpos($raw, "\r\n\r\n");

                if ($headEnd !== false && strlen($raw) > $headEnd + 4 + 4) {
                    break;
                }
            }

            $socket->close();
            $headEnd = strpos($raw, "\r\n\r\n");

            if ($headEnd === false || !str_starts_with($raw, 'HTTP/1.1 101')) {
                return '';
            }

            $rest = substr($raw, $headEnd + 4);
            $unframed = '';

            while (strlen($rest) >= 2) {
                $opcode = ord($rest[0]) & 0x0F;
                $this->assertSame(0x02, $opcode, 'VLESS over WebSocket uses binary frames');
                $len = ord($rest[1]) & 0x7F;
                $unframed .= substr($rest, 2, $len);
                $rest = substr($rest, 2 + $len);
            }

            return $unframed;
        });
    }

    private static function freePort(): int
    {
        $probe = stream_socket_server('tcp://127.0.0.1:0') ?: throw new RuntimeException('no port');
        $port = (int) substr(strrchr((string) stream_socket_get_name($probe, false), ':'), 1);
        fclose($probe);

        return $port;
    }
}
