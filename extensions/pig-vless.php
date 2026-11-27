<?php

declare(strict_types=1);

use Pig\CodingAgent\Extensions\ExtensionApi;
use Pig\CodingAgent\Extensions\Events\SessionShutdownEvent;
use Pig\CodingAgent\Extensions\Events\SessionStartEvent;
use Pig\CodingAgent\Extensions\ExtensionContext;
use Pig\CodingAgent\Logger;
use PigVless\Reality;
use PigVless\VlessServer;

/*
 * The file is named after the extension because pig names an extension by its file: settings
 * that say `"disabledExtensions": ["pig-vless"]` from the days it was bundled with pig still
 * reach it.
 *
 * A package installed from git is not run through Composer, so nothing autoloads its classes;
 * this registers the loader for the package's own namespace, once.
 */
spl_autoload_register(static function (string $class): void {
    if (str_starts_with($class, 'PigVless\\')) {
        $file = dirname(__DIR__) . '/src/' . str_replace('\\', '/', substr($class, 9)) . '.php';

        if (is_file($file)) {
            require_once $file;
        }
    }
});

/**
 * A VLESS inbound beside the agent, so a phone can go through this machine.
 *
 * Loading it fills in `settings.json` — a listen address and a UUID, made once and kept, so the
 * phone's link stays valid across restarts — but **listens on nothing until asked**:
 * `/vless start`. `/web`'s shape: `start | stop | restart | status | keygen`, and the bare command
 * is `status`, because a proxy port is not something to open by accident. The session ending stops
 * it.
 *
 *     "vless": {
 *       "listen": "0.0.0.0:10086",      // written on first load
 *       "uuid":   "…",                   // likewise
 *       "cert":   "/path/fullchain.pem", // optional; both set → TLS, else plain
 *       "key":    "/path/privkey.pem",
 *       "wsPath": "/vless",              // optional; when set → WebSocket, else raw TCP
 *       "reality": {                     // optional; when set → REALITY + XTLS Vision
 *         "privateKey": "…",
 *         "publicKey":  "…",
 *         "dest":       "www.apple.com:443",
 *         "serverNames": ["www.apple.com"],
 *         "shortIds":   ["a1b2c3d4"]
 *       }
 *     }
 */
return static function (ExtensionApi $pig): void {
    /** @var VlessServer|null the server as configured, started or not */
    $server = null;
    $running = false;
    $problem = null;

    $buildServer = static function () use ($pig, &$server, &$problem): void {
        $settings = $pig->getSettings();
        $config = $settings?->get('vless');
        $config = is_array($config) ? $config : [];

        $listen = $config['listen'] ?? null;

        if (!is_string($listen) || $listen === '') {
            $listen = '0.0.0.0:10086';
            $settings?->set('vless.listen', $listen);
        }

        $uuid = $config['uuid'] ?? null;

        if (!is_string($uuid) || $uuid === '') {
            $bytes = random_bytes(16);
            $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
            $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
            $hex = bin2hex($bytes);
            $uuid = substr($hex, 0, 8) . '-' . substr($hex, 8, 4) . '-' . substr($hex, 12, 4) . '-' . substr($hex, 16, 4) . '-' . substr($hex, 20);
            $settings?->set('vless.uuid', $uuid);
        }

        $reality = is_array($config['reality'] ?? null) ? $config['reality'] : null;
        if ($reality !== null && ($reality['enabled'] ?? true) !== false) {
            if (!is_string($reality['privateKey'] ?? null) || trim($reality['privateKey']) === '') {
                $pair = Reality::generateKeyPair();
                $reality['privateKey'] = $pair['privateKey'];
                $reality['publicKey'] = $pair['publicKey'];
                $settings?->set('vless.reality.privateKey', $pair['privateKey']);
                $settings?->set('vless.reality.publicKey', $pair['publicKey']);
            }
            if (!isset($reality['shortIds']) && !isset($reality['shortId'])) {
                $sid = bin2hex(random_bytes(4));
                $reality['shortIds'] = [$sid];
                $settings?->set('vless.reality.shortIds', [$sid]);
            }
        } else {
            $reality = null;
        }

        [$host, $port] = str_contains($listen, ':') ? explode(':', $listen, 2) : [$listen, '10086'];
        $wsPath = $config['wsPath'] ?? $config['path'] ?? null;

        try {
            $server = new VlessServer(
                $host,
                ctype_digit($port) ? (int) $port : 10086,
                $uuid,
                is_string($config['cert'] ?? null) ? $config['cert'] : null,
                is_string($config['key'] ?? null) ? $config['key'] : null,
                is_string($wsPath) ? $wsPath : null,
                $reality,
            );
            $problem = null;
        } catch (Throwable $e) {
            $server = null;
            $problem = $e->getMessage();
            Logger::warning("[vless] bad configuration: {$problem}");
        }
    };

    $pig->on('session_start', static function (SessionStartEvent $event, ExtensionContext $ctx) use ($buildServer): void {
        $buildServer();
    });

    $pig->on('session_shutdown', static function (SessionShutdownEvent $event, ExtensionContext $ctx) use (&$server, &$running): void {
        if ($running) {
            $server?->stop();
            $running = false;
        }
    });

    $pig->registerCommand(
        'vless',
        static function (string $args, ExtensionContext $ctx) use ($pig, $buildServer, &$server, &$running, &$problem): void {
            $say = static function (string $text, string $level = 'info') use ($ctx): void {
                if ($ctx->hasUi) {
                    $ctx->ui->notify($text, $level);
                } else {
                    echo $text, "\n";
                }
            };

            $action = strtolower(trim($args));

            if ($action === '') {
                $action = 'status';
            }

            if ($action === 'keygen') {
                $pair = Reality::generateKeyPair();
                $sid = bin2hex(random_bytes(4));
                $settings = $pig->getSettings();
                $settings?->set('vless.reality.privateKey', $pair['privateKey']);
                $settings?->set('vless.reality.publicKey', $pair['publicKey']);
                if ($settings?->get('vless.reality.dest') === null) {
                    $settings?->set('vless.reality.dest', 'www.apple.com:443');
                }
                if ($settings?->get('vless.reality.serverNames') === null) {
                    $settings?->set('vless.reality.serverNames', ['www.apple.com']);
                }
                if ($settings?->get('vless.reality.shortIds') === null) {
                    $settings?->set('vless.reality.shortIds', [$sid]);
                }
                $wasRunning = $running;
                if ($wasRunning) {
                    $server?->stop();
                    $running = false;
                }
                $buildServer();
                if ($wasRunning && $server !== null) {
                    $server->start();
                    $running = true;
                }
                $say(
                    "Generated REALITY X25519 key pair (saved to vless.reality):\n"
                    . "PrivateKey: {$pair['privateKey']}\n"
                    . "PublicKey:  {$pair['publicKey']}",
                    'info',
                );

                return;
            }

            if (!in_array($action, ['start', 'stop', 'restart', 'status'], true)) {
                $say('Usage: /vless start | stop | restart | status | keygen', 'warning');

                return;
            }

            if ($server === null) {
                $say('VLESS cannot run: ' . ($problem ?? 'the session has not started yet'), 'warning');

                return;
            }

            if ($action === 'stop' || $action === 'restart') {
                if ($running) {
                    $server->stop();
                    $running = false;
                    Logger::info('[vless] stopped');
                }

                if ($action === 'stop') {
                    $say('VLESS stopped.');

                    return;
                }
            }

            $mode = match (true) {
                $server->isReality() => 'TCP + REALITY' . ($server->reality['flow'] !== '' ? " ({$server->reality['flow']})" : ''),
                default => ($server->isWs() ? "WS {$server->wsPath}" : 'TCP') . ($server->isTls() ? ' + TLS' : ''),
            };

            if ($action === 'start' || $action === 'restart') {
                if ($running) {
                    $say("VLESS is already listening on {$server->host}:{$server->port} ({$mode}).");

                    return;
                }

                try {
                    $server->start();
                    $running = true;
                    Logger::info("[vless] listening on {$server->host}:{$server->port} ({$mode})");
                } catch (Throwable $e) {
                    $say("VLESS could not start: {$e->getMessage()}", 'warning');

                    return;
                }
            }

            $where = $server->host === '0.0.0.0' || $server->host === '::' ? '<this machine\'s address>' : $server->host;
            $say(
                ($running
                    ? "VLESS listening on {$server->host}:{$server->port} ({$mode}), {$server->connections()} socket(s) open."
                    : "VLESS is not listening (configured for {$server->host}:{$server->port}, {$mode}). `/vless start` opens it.")
                . "\nLink for the phone: " . $server->shareLink($where),
                $running ? 'info' : 'warning',
            );
        },
        'VLESS inbound: start | stop | restart | status | keygen',
    );
};
