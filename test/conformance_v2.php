<?php
/**
 * v2 authenticated-handshake conformance for the PHP SDK.
 *
 * Replays the shared golden vectors (test/vectors/adatp-v2-handshake-vectors.json,
 * copied from the server repo) and checks this SDK reproduces them byte-for-byte.
 * No server needed. Run: php test/conformance_v2.php
 */
require __DIR__ . '/../vendor/autoload.php';

use AdaTP\Crypto\HandshakeV2;
use AdaTP\Crypto\AdaTPHandshakeException;

$vectors = json_decode(file_get_contents(__DIR__ . '/vectors/adatp-v2-handshake-vectors.json'), true);
$cases = [];
foreach ($vectors['cases'] as $c) {
    $cases[$c['id']] = $c;
}
function h($s) { return hex2bin($s); }

$fails = 0;
function check($cond, $name) {
    global $fails;
    echo ($cond ? "  ok   " : "  FAIL ") . $name . "\n";
    if (!$cond) $fails++;
}

// 1. transcript hash
$tc = $cases['handshake-v2-transcript-hash'];
$th = HandshakeV2::transcriptHash(h($tc['input']['epk_c_hex']), h($tc['input']['epk_s_hex']), h($tc['input']['spk_s_hex']));
check(bin2hex($th) === $tc['expected']['transcript_hash_hex'], 'transcript hash matches Rust reference');

// 2. signed ServerHello verifies under the pinned key
$sh = $cases['handshake-v2-server-hello'];
$pinned = h($tc['input']['spk_s_hex']);
list($epkS, $th2) = HandshakeV2::verifyServerHello($pinned, h($sh['input']['epk_c_hex']), h($sh['expected']['server_hello_hex']));
check(bin2hex($epkS) === $sh['input']['epk_s_hex'] && bin2hex($th2) === $tc['expected']['transcript_hash_hex'],
      'signed ServerHello accepted; epk_s + th recovered');

// 3. wrong pin rejected
$wp = $cases['handshake-v2-server-hello-wrong-pin'];
try {
    HandshakeV2::verifyServerHello(h($wp['input']['pinned_spk_s_hex']), h($wp['input']['epk_c_hex']), h($wp['input']['server_hello_hex']));
    check(false, 'wrong pin rejected');
} catch (AdaTPHandshakeException $e) {
    check($e->errorCode === 'unknown_identity', 'wrong pin rejected (unknown_identity)');
}

// 4. substituted ephemeral rejected
$te = $cases['handshake-v2-server-hello-tampered-ephemeral'];
try {
    HandshakeV2::verifyServerHello(h($te['input']['pinned_spk_s_hex']), h($te['input']['epk_c_hex']), h($te['input']['server_hello_hex']));
    check(false, 'substituted ephemeral rejected');
} catch (AdaTPHandshakeException $e) {
    check($e->errorCode === 'signature_verification_failed', 'substituted ephemeral rejected (signature_verification_failed)');
}

// 5. malformed length rejected
try {
    HandshakeV2::verifyServerHello(str_repeat("\0", 32), str_repeat("\0", 32), str_repeat("\0", 127));
    check(false, 'malformed rejected');
} catch (AdaTPHandshakeException $e) {
    check($e->errorCode === 'malformed_server_hello', 'malformed response length rejected');
}

// 6. Finished plaintext
$fc = $cases['handshake-v2-finished'];
check(bin2hex(HandshakeV2::finishedPlaintext(h($fc['input']['transcript_hash_hex']))) === $fc['expected']['finished_plaintext_hex'],
      'Finished plaintext matches Rust reference');

echo "\nPHP v2 handshake conformance: " . ($fails === 0 ? "PASS" : "FAIL") . " ($fails failure" . ($fails === 1 ? "" : "s") . ")\n";
exit($fails === 0 ? 0 : 1);
