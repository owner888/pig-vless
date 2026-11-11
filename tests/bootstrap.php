<?php

declare(strict_types=1);

/*
 * The tests run against a pig checkout: its Composer autoloader brings PHPUnit and pig's own
 * classes (`Pig\Async\*`, `Pig\CodingAgent\Web\*`). Where pig is: $PIG_DIR, else a `pig`
 * directory next to this package.
 *
 *     PIG_DIR=~/path/to/pig ~/path/to/pig/vendor/bin/phpunit -c phpunit.xml
 */

$pig = getenv('PIG_DIR') ?: dirname(__DIR__, 2) . '/pig';
$autoload = rtrim($pig, '/') . '/vendor/autoload.php';

if (!is_file($autoload)) {
    fwrite(STDERR, "pig-vless tests need a pig checkout with vendor/ installed; set PIG_DIR (tried {$pig}).\n");
    exit(1);
}

require $autoload;

spl_autoload_register(static function (string $class): void {
    foreach (['PigVless\\Test\\' => __DIR__ . '/', 'PigVless\\' => dirname(__DIR__) . '/src/'] as $prefix => $directory) {
        if (str_starts_with($class, $prefix)) {
            $file = $directory . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';

            if (is_file($file)) {
                require_once $file;
            }

            return;
        }
    }
});

$home = sys_get_temp_dir() . '/pig-vless-test-home-' . getmypid() . '-' . bin2hex(random_bytes(3));
mkdir($home, 0o700, true);
putenv("HOME={$home}");
$_ENV['HOME'] = $_SERVER['HOME'] = $home;

register_shutdown_function(static function () use ($home): void {
    exec('rm -rf ' . escapeshellarg($home));
});
