<?php

namespace AdaTP\Crypto;

/**
 * AdaTP protocol v2 — client side of the authenticated (SIGMA-style) handshake.
 *
 * Mirrors the Rust reference server (core/src/session/handshake_v2.rs) and the
 * ProVerif-verified design byte-for-byte. The security-relevant step is here:
 * the client checks (1) the server key equals the pinned key, then (2) the
 * Ed25519 signature over the transcript, BEFORE deriving any key material.
 */
class HandshakeV2
{
    const PROTOCOL_V2 = 2;
    const LABEL_HS = "AdaTP-v2-handshake";
    const FINISHED_LABEL = "AdaTP-v2-finished";
    const SERVER_HELLO_LEN = 128; // epk_s(32) || spk_s(32) || sig(64)

    /** th = SHA-256(LABEL_HS || 0x02 || epk_c || epk_s || spk_s). */
    public static function transcriptHash(string $epkC, string $epkS, string $spkS): string
    {
        return hash('sha256', self::LABEL_HS . chr(self::PROTOCOL_V2) . $epkC . $epkS . $spkS, true);
    }

    public static function verifyEd25519(string $pub, string $msg, string $sig): bool
    {
        if (strlen($pub) !== 32 || strlen($sig) !== 64) {
            return false;
        }
        try {
            return sodium_crypto_sign_verify_detached($sig, $msg, $pub);
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * Verify a v2 HandshakeResponse against the pinned server identity.
     * Returns [epk_s, transcript_hash] on success; throws
     * AdaTPHandshakeException (malformed_server_hello | unknown_identity |
     * signature_verification_failed) otherwise. Derives no key material.
     */
    public static function verifyServerHello(string $pinnedSpkS, string $epkC, string $response): array
    {
        if (strlen($response) !== self::SERVER_HELLO_LEN) {
            throw new AdaTPHandshakeException(
                'malformed_server_hello',
                'expected ' . self::SERVER_HELLO_LEN . ' bytes, got ' . strlen($response)
            );
        }
        $epkS = substr($response, 0, 32);
        $spkS = substr($response, 32, 32);
        $sig  = substr($response, 64, 64);

        // (1) Identity: constant-time compare against the pinned key.
        if (strlen($pinnedSpkS) !== 32 || !hash_equals($pinnedSpkS, $spkS)) {
            throw new AdaTPHandshakeException('unknown_identity', 'server key does not match the pinned key');
        }
        // (2) Authenticity: re-derive th and check the signature under the pinned key.
        $th = self::transcriptHash($epkC, $epkS, $spkS);
        if (!self::verifyEd25519($spkS, $th, $sig)) {
            throw new AdaTPHandshakeException('signature_verification_failed', 'server signature did not verify');
        }
        return [$epkS, $th];
    }

    /** The client's key-confirmation plaintext: FINISHED_LABEL || th. */
    public static function finishedPlaintext(string $th): string
    {
        return self::FINISHED_LABEL . $th;
    }

    /** Accept a pinned key as a 64-char hex string or 32 raw bytes. */
    public static function normalizePinnedKey($key): string
    {
        $bytes = (strlen($key) === 64 && ctype_xdigit($key)) ? hex2bin($key) : $key;
        if (strlen($bytes) !== 32) {
            throw new AdaTPHandshakeException(
                'invalid_pinned_key', 'pinned server key must be 32 bytes (got ' . strlen($bytes) . ')'
            );
        }
        return $bytes;
    }
}
