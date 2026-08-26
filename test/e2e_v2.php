<?php
/**
 * v2 end-to-end client: connects to a live AdaTP server with a pinned key, runs
 * the authenticated handshake, then an encrypted auth + join + text round-trip
 * (which only works if the AAD-bound v2 session agrees end to end). Exit 0 on
 * success. Driven by test/run_e2e_v2.sh.
 *
 * usage: php test/e2e_v2.php <host> <port> <server_key_hex(64) | v1>
 */
require __DIR__ . '/../vendor/autoload.php';

use AdaTP\Client;

$host = $argv[1] ?? '127.0.0.1';
$port = (int)($argv[2] ?? 3195);
$key = $argv[3] ?? getenv('ADATP_SERVER_KEY');
$v1 = ($key === 'v1');
if (!$v1 && (!$key || strlen($key) !== 64)) {
    fwrite(STDERR, "usage: e2e_v2.php <host> <port> <server_key_hex(64) | v1>\n");
    exit(2);
}

try {
    $client = new Client($host, $port, '/ws', false, 'en', $v1 ? null : $key);
    $client->connect(); // v2 handshake (verify + AAD) unless v1
    $me = $client->authenticate('guest', '');
    if (($me['role'] ?? '') !== 'anonymous') {
        throw new Exception('unexpected identity: ' . json_encode($me));
    }
    $client->joinRoom('lobby');
    $client->sendTextMessage('hello from PHP');
    $client->disconnect();
    $label = $v1 ? 'v1' : 'v2';
    $extra = $v1 ? '' : ' with header-AAD';
    echo "PHP E2E $label PASSED: handshake + round-trip (auth + join + text)$extra.\n";
    exit(0);
} catch (\Throwable $e) {
    fwrite(STDERR, "PHP E2E FAILED: " . $e->getMessage() . "\n");
    exit(1);
}
