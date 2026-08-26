<?php

namespace AdaTP\Crypto;

class SecureSession
{
    private $clientWriteKey;
    private $serverWriteKey;
    private $clientIvRoot;
    private $serverIvRoot;
    
    private $mySequence = 1;
    private $peerSequence = 1;
    
    private $role; // 'client' or 'server'
    // When true (protocol v2), the 45-byte frame header is bound as AEAD AAD.
    private $bindAad = false;

    public function __construct(string $role, string $sharedSecret, bool $bindAad = false)
    {
        $this->role = $role;
        $this->bindAad = $bindAad;
        $keys = KeyDerivation::deriveSessionKeys($sharedSecret);
        
        $this->clientWriteKey = $keys['client_write'];
        $this->serverWriteKey = $keys['server_write'];
        $this->clientIvRoot = $keys['client_iv'];
        $this->serverIvRoot = $keys['server_iv'];
    }

    /** The next sequence number this session will use for encrypt(). */
    public function getMySequence(): int
    {
        return $this->mySequence;
    }

    public function encrypt(string $plaintext, string $aad = ''): array
    {
        $seq = $this->mySequence;
        $iv = $this->computeIv($seq, $this->role);

        $key = ($this->role === 'client') ? $this->clientWriteKey : $this->serverWriteKey;

        // AES-256-GCM. v2 binds the header as AAD (7th arg); v1 passes '' (empty).
        $ad = ($this->bindAad ? $aad : '');
        $tag = "";
        $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, $ad, 16);

        if ($ciphertext === false) {
            throw new \Exception("Encryption failed: " . openssl_error_string());
        }

        $this->mySequence++;

        return [
            'ciphertext' => $ciphertext,
            'tag' => $tag,
            'sequence' => $seq
        ];
    }

    public function decrypt(string $ciphertext, string $authTag, int $sequence, string $aad = ''): string
    {
        $peerRole = ($this->role === 'client') ? 'server' : 'client';
        $iv = $this->computeIv($sequence, $peerRole);

        $key = ($peerRole === 'client') ? $this->clientWriteKey : $this->serverWriteKey;

        $ad = ($this->bindAad ? $aad : '');
        $plaintext = openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $authTag, $ad);
        
        if ($plaintext === false) {
             throw new \Exception("Decryption failed or auth tag invalid.");
        }
        
        if ($sequence >= $this->peerSequence) {
            $this->peerSequence = $sequence + 1;
        }
        
        return $plaintext;
    }

    private function computeIv(int $sequence, string $role): string
    {
        $root = ($role === 'client') ? $this->clientIvRoot : $this->serverIvRoot;
        
        // XOR last 8 bytes with Sequence (Little Endian)
        // Root is 12 bytes.
        // Sequence is 64-bit uint. PHP ints are 64-bit signed/unsigned?
        // pack('P', $sequence) gives 64-bit Little Endian.
        
        $seqBytes = pack('P', $sequence);
        $iv = $root; // String copy
        
        // XOR bytes [4..11] with seqBytes [0..7]
        for ($i = 0; $i < 8; $i++) {
            $iv[4 + $i] = $iv[4 + $i] ^ $seqBytes[$i];
        }
        
        return $iv;
    }
}
