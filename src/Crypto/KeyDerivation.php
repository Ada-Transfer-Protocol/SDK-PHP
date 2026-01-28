<?php

namespace AdaTP\Crypto;

class KeyDerivation
{
    /**
     * Derives session keys using HKDF-SHA256.
     * 
     * @param string $sharedSecret The shared secret from ECDH.
     * @param string|null $salt Since Rust uses [0u8; 32], we default to that if null.
     * @return array Contains keys: client_write, server_write, client_iv, server_iv
     */
    public static function deriveSessionKeys(string $sharedSecret, ?string $salt = null): array
    {
        if ($salt === null) {
            $salt = str_repeat("\0", 32);
        }

        // Algo, IKM, LENGTH, INFO, SALT
        // Rust::HKDF::extract(salt, secret) -> prk
        // prk.expand(info, len)
        
        // PHP's hash_hkdf does extract + expand in one go usually, 
        // or we can control it.
        // hash_hkdf(algo, ikm, length, info, salt)
        
        $clientWriteKey = hash_hkdf('sha256', $sharedSecret, 32, 'client_write', $salt);
        $serverWriteKey = hash_hkdf('sha256', $sharedSecret, 32, 'server_write', $salt);
        $clientIvRoot = hash_hkdf('sha256', $sharedSecret, 12, 'client_iv', $salt);
        $serverIvRoot = hash_hkdf('sha256', $sharedSecret, 12, 'server_iv', $salt);

        return [
            'client_write' => $clientWriteKey,
            'server_write' => $serverWriteKey,
            'client_iv' => $clientIvRoot,
            'server_iv' => $serverIvRoot,
        ];
    }
}
