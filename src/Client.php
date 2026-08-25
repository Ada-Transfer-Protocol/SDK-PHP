<?php

namespace AdaTP;

/**
 * AdaTP client for PHP.
 *
 * Transport is WebSocket (binary frames, one AdaTP packet per message).
 * connect() performs the X25519 handshake (libsodium) so all subsequent
 * traffic is encrypted with AES-256-GCM.
 *
 *     $client = new Client('127.0.0.1', 3000);
 *     $client->connect();
 *     $client->authenticate('user1', 'password123');
 *     $client->joinRoom('lobby');
 *     $client->sendTextMessage('Hello!');
 *
 * A full URL is also accepted: new Client('wss://example.com/ws')
 */
class Client
{
    /** Locales supported by the SDK's language option. */
    public const LOCALES = ['en', 'tr', 'it', 'fr', 'de', 'zh', 'ja', 'hi', 'ar'];

    private $url;
    private $transport;

    public $cryptoSession;
    private $sessionId;
    private $inbox = [];

    /** SDK language (client-side metadata; the wire protocol is language-neutral). */
    private $locale = 'en';

    public function __construct(string $hostOrUrl, int $port = 3000, string $path = '/ws', bool $secure = false, string $locale = 'en')
    {
        $this->locale = in_array($locale, self::LOCALES, true) ? $locale : 'en';
        if (strpos($hostOrUrl, 'ws://') === 0 || strpos($hostOrUrl, 'wss://') === 0) {
            $this->url = $hostOrUrl;
        } else {
            $scheme = $secure ? 'wss' : 'ws';
            $this->url = "$scheme://$hostOrUrl:$port$path";
        }
        $this->sessionId = \Ramsey\Uuid\Uuid::uuid4()->getBytes();
    }

    /** Switches the SDK language at runtime (one of LOCALES). */
    public function setLocale(string $locale): void
    {
        $this->locale = in_array($locale, self::LOCALES, true) ? $locale : 'en';
    }

    public function getLocale(): string
    {
        return $this->locale;
    }

    public function connect()
    {
        $this->transport = new WebSocketTransport();
        $this->transport->connect($this->url);

        echo "Connected to {$this->url}. Starting handshake...\n";
        $this->handshake();
    }

    private function handshake()
    {
        // 1. Ephemeral X25519 key pair
        $keypair = sodium_crypto_box_keypair();
        $mySecret = sodium_crypto_box_secretkey($keypair);
        $myPublic = sodium_crypto_box_publickey($keypair);

        // 2. HANDSHAKE_INIT carries our public key
        $packet = new Packet(Protocol::MSG_HANDSHAKE_INIT, $myPublic, $this->sessionId);
        $this->sendPacket($packet);

        // 3. HANDSHAKE_RESPONSE carries the server's public key
        $response = $this->readPacketOfType([Protocol::MSG_HANDSHAKE_RESPONSE]);
        $serverPublic = substr($response->payload, 0, 32);
        if (strlen($serverPublic) < 32) {
            throw new \Exception("Server did not provide a key");
        }

        // 4. Shared secret + session keys
        $sharedSecret = sodium_crypto_scalarmult($mySecret, $serverPublic);
        $this->cryptoSession = new Crypto\SecureSession('client', $sharedSecret);

        // 5. HANDSHAKE_COMPLETE proves both sides derived the same keys
        $encrypted = $this->cryptoSession->encrypt("Verification OK");
        $completePacket = new Packet(Protocol::MSG_HANDSHAKE_COMPLETE, $encrypted['ciphertext'], $this->sessionId);
        $completePacket->header->flags |= Protocol::FLAG_ENCRYPTED;
        $completePacket->header->sequence = $encrypted['sequence'];
        $completePacket->authTag = $encrypted['tag'];

        $this->sendPacket($completePacket);
        echo "Handshake complete.\n";
    }

    public function authenticate(string $username, string $password): array
    {
        if (!$this->cryptoSession) {
            throw new \Exception("No secure session (call connect() first)");
        }

        $payload = json_encode(['username' => $username, 'password' => $password]);
        $this->sendEncryptedPacket(Protocol::MSG_AUTH_REQUEST, $payload);

        $response = $this->readPacketOfType([Protocol::MSG_AUTH_SUCCESS, Protocol::MSG_AUTH_FAILURE]);
        $decrypted = $this->decryptPacket($response);

        if ($response->header->msgType === Protocol::MSG_AUTH_SUCCESS) {
            $identity = json_decode($decrypted, true);
            echo "Auth success: $decrypted\n";
            return is_array($identity) ? $identity : [];
        }
        throw new \Exception("Auth failed: $decrypted");
    }

    /** Joins a room and blocks until the server confirms with ROOM_JOINED. */
    public function joinRoom(string $roomName): string
    {
        if (!$this->cryptoSession) {
            throw new \Exception("No secure session.");
        }

        $this->sendEncryptedPacket(Protocol::MSG_JOIN_ROOM, $roomName);
        $response = $this->readPacketOfType([Protocol::MSG_ROOM_JOINED, Protocol::MSG_AUTH_FAILURE]);
        $decrypted = $this->decryptPacket($response);
        if ($response->header->msgType !== Protocol::MSG_ROOM_JOINED) {
            throw new \Exception("Join failed: $decrypted");
        }
        return $decrypted;
    }

    public function sendTextMessage(string $text)
    {
        if (!$this->cryptoSession) {
            throw new \Exception("No secure session.");
        }
        $this->sendEncryptedPacket(Protocol::MSG_TEXT_MESSAGE, $text);
    }

    /** Blocks until the next TEXT_MESSAGE arrives; returns the plaintext. */
    public function readTextMessage(): string
    {
        $packet = $this->readPacketOfType([Protocol::MSG_TEXT_MESSAGE]);
        return $this->decryptPacket($packet);
    }

    /** Broadcasts a game state (array → JSON, or raw string) to the room. */
    public function sendGameState($state)
    {
        $payload = is_string($state) ? $state : json_encode($state);
        $this->sendEncryptedPacket(Protocol::MSG_GAME_STATE, $payload);
    }

    /** Blocks until the next GAME_STATE arrives; returns array (or string). */
    public function readGameState()
    {
        $packet = $this->readPacketOfType([Protocol::MSG_GAME_STATE]);
        $raw = $this->decryptPacket($packet);
        $decoded = json_decode($raw, true);
        return $decoded !== null ? $decoded : $raw;
    }

    /** Calls a server-side tool; returns the result or throws on error. */
    public function callTool(string $tool, array $args = [])
    {
        $callId = \Ramsey\Uuid\Uuid::uuid4()->toString();
        $body = json_encode(['id' => $callId, 'tool' => $tool, 'args' => (object)$args]);
        $this->sendEncryptedPacket(Protocol::MSG_TOOL_CALL, $body);

        for ($i = 0; $i < 256; $i++) {
            $packet = $this->readPacketOfType([Protocol::MSG_TOOL_RESULT, Protocol::MSG_TOOL_ERROR]);
            $parsed = json_decode($this->decryptPacket($packet), true);
            if (($parsed['id'] ?? null) !== $callId) {
                continue;
            }
            if ($packet->header->msgType === Protocol::MSG_TOOL_RESULT && ($parsed['ok'] ?? false)) {
                return $parsed['result'] ?? null;
            }
            $err = $parsed['error'] ?? ['code' => 'tool_failed', 'message' => 'unknown'];
            throw new \Exception("Tool '$tool' failed: {$err['code']}: {$err['message']}");
        }
        throw new \Exception("No response for tool '$tool'");
    }

    /** Lists the tools available on the server. */
    public function listTools(): array
    {
        $result = $this->callTool('system.list_tools');
        return $result['tools'] ?? [];
    }

    public function sendFile(string $filePath)
    {
        if (!file_exists($filePath)) {
            throw new \Exception("File not found: $filePath");
        }

        $filename = basename($filePath);
        $size = filesize($filePath);
        $fileId = \Ramsey\Uuid\Uuid::uuid4()->toString();
        $fileIdBytes = \Ramsey\Uuid\Uuid::fromString($fileId)->getBytes();

        $initData = json_encode([
            'id' => $fileId,
            'filename' => $filename,
            'size' => $size
        ]);
        $this->sendEncryptedPacket(Protocol::MSG_FILE_INIT, $initData);

        echo "Sending file $filename ($size bytes)...\n";

        $handle = fopen($filePath, "rb");
        if ($handle === false) throw new \Exception("Cannot open file");

        while (!feof($handle)) {
            $chunk = fread($handle, 16384);
            if ($chunk === false || strlen($chunk) === 0) break;
            $this->sendEncryptedPacket(Protocol::MSG_FILE_CHUNK, $fileIdBytes . $chunk);
        }
        fclose($handle);

        $this->sendEncryptedPacket(Protocol::MSG_FILE_COMPLETE, $fileIdBytes);
        echo "File sent.\n";
    }

    public function decryptPacket(Packet $packet): string
    {
        if ($packet->header->flags & Protocol::FLAG_ENCRYPTED) {
            return $this->cryptoSession->decrypt($packet->payload, $packet->authTag, $packet->header->sequence);
        }
        return $packet->payload;
    }

    public function disconnect()
    {
        if ($this->transport && $this->transport->isConnected()) {
            try {
                $packet = new Packet(Protocol::MSG_DISCONNECT, "", $this->sessionId);
                $this->sendPacket($packet);
            } catch (\Exception $e) {
                // best effort
            }
            $this->transport->close();
        }
    }

    public function close()
    {
        if ($this->transport) {
            $this->transport->close();
        }
    }

    /**
     * Underlying PHP stream — usable with stream_select() for event loops.
     * Note: check hasPending() first; buffered packets are invisible to
     * stream_select().
     */
    public function getSocket()
    {
        return $this->transport ? $this->transport->getStream() : null;
    }

    /** True if a packet can be read without touching the network. */
    public function hasPending(): bool
    {
        return !empty($this->inbox) || ($this->transport && $this->transport->hasBuffered());
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    private function sendEncryptedPacket(int $type, string $payload)
    {
        $enc = $this->cryptoSession->encrypt($payload);
        $packet = new Packet($type, $enc['ciphertext'], $this->sessionId);
        $packet->header->flags |= Protocol::FLAG_ENCRYPTED;
        $packet->header->sequence = $enc['sequence'];
        $packet->authTag = $enc['tag'];
        $this->sendPacket($packet);
    }

    private function sendPacket(Packet $packet)
    {
        $this->transport->sendBinary(Packet::encode($packet));
    }

    /** Returns the next packet (queued packets first, then the wire). */
    public function readPacket(): Packet
    {
        if (!empty($this->inbox)) {
            return array_shift($this->inbox);
        }
        $frame = $this->transport->recvBinary();
        if ($frame === null) {
            throw new \Exception("Connection closed");
        }
        if (strlen($frame) < Protocol::HEADER_SIZE) {
            throw new \Exception("Frame too short");
        }
        return Packet::decode($frame);
    }

    /**
     * Returns the next packet matching one of $types; unrelated packets
     * (presence updates, chat traffic) are queued for later reads.
     */
    public function readPacketOfType(array $types, int $maxSkipped = 256): Packet
    {
        $skipped = [];
        try {
            while (count($skipped) <= $maxSkipped) {
                $packet = $this->readPacket();
                if (in_array($packet->header->msgType, $types, true)) {
                    return $packet;
                }
                $skipped[] = $packet;
            }
            throw new \Exception("Too much unrelated traffic while waiting for packet");
        } finally {
            $this->inbox = array_merge($skipped, $this->inbox);
        }
    }
}
