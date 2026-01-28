<?php

namespace AdaTP;

class Client
{
    private $host;
    private $port;
    private $socket;
    
    public $cryptoSession;
    private $sessionId;

    public function __construct(string $host, int $port)
    {
        $this->host = $host;
        $this->port = $port;
        // Generate a random session ID
        $this->sessionId = \Ramsey\Uuid\Uuid::uuid4()->getBytes();
    }

    public function connect()
    {
        $this->socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        if ($this->socket === false) {
            throw new \Exception("socket_create() failed: " . socket_strerror(socket_last_error()));
        }

        $result = socket_connect($this->socket, $this->host, $this->port);
        if ($result === false) {
            throw new \Exception("socket_connect() failed: " . socket_strerror(socket_last_error($this->socket)));
        }

        echo "Connected. Starting handshake...\n";
        $this->handshake();
    }

    private function handshake()
    {
        // 1. Generate Ephemeral Keys (X25519)
        // sodium_crypto_box_keypair generates 32-byte secret + 32-byte public
        $keypair = sodium_crypto_box_keypair();
        $mySecret = sodium_crypto_box_secretkey($keypair);
        $myPublic = sodium_crypto_box_publickey($keypair);

        // 2. Send HANDSHAKE_INIT
        $packet = new Packet(Protocol::MSG_HANDSHAKE_INIT, $myPublic, $this->sessionId);
        $this->sendPacket($packet);

        // 3. Receive HANDSHAKE_RESPONSE
        $response = $this->readPacket();
        if ($response->header->msgType !== Protocol::MSG_HANDSHAKE_RESPONSE) {
            throw new \Exception("Expected HANDSHAKE_RESPONSE, got " . $response->header->msgType);
        }

        $serverPublic = substr($response->payload, 0, 32);

        // 4. Compute Shared Secret
        $sharedSecret = sodium_crypto_scalarmult($mySecret, $serverPublic);

        // 5. Init Crypto Session
        $this->cryptoSession = new Crypto\SecureSession('client', $sharedSecret);

        // 6. Send HANDSHAKE_COMPLETE (Encrypted)
        $verifyMsg = "Verification OK";
        $encrypted = $this->cryptoSession->encrypt($verifyMsg);

        $completePacket = new Packet(Protocol::MSG_HANDSHAKE_COMPLETE, $encrypted['ciphertext'], $this->sessionId);
        $completePacket->header->flags |= Protocol::FLAG_ENCRYPTED;
        $completePacket->header->sequence = $encrypted['sequence'];
        $completePacket->authTag = $encrypted['tag'];

        $this->sendPacket($completePacket);
        echo "Handshake Complete!\n";
    }

    public function decryptPacket(Packet $packet): string
    {
        if ($packet->header->flags & Protocol::FLAG_ENCRYPTED) {
            return $this->cryptoSession->decrypt($packet->payload, $packet->authTag, $packet->header->sequence);
        }
        return $packet->payload;
    }

    public function sendTextMessage(string $text)
    {
        if (!$this->cryptoSession) {
             throw new \Exception("No secure session.");
        }

        $encrypted = $this->cryptoSession->encrypt($text);
        
        $packet = new Packet(Protocol::MSG_TEXT_MESSAGE, $encrypted['ciphertext'], $this->sessionId);
        $packet->header->flags |= Protocol::FLAG_ENCRYPTED;
        $packet->header->sequence = $encrypted['sequence'];
        $packet->authTag = $encrypted['tag'];
        
        $this->sendPacket($packet);
    }
    
    public function joinRoom(string $roomName)
    {
        if (!$this->cryptoSession) {
             throw new \Exception("No secure session.");
        }

        $encrypted = $this->cryptoSession->encrypt($roomName);
        
        $packet = new Packet(Protocol::MSG_JOIN_ROOM, $encrypted['ciphertext'], $this->sessionId);
        $packet->header->flags |= Protocol::FLAG_ENCRYPTED;
        $packet->header->sequence = $encrypted['sequence'];
        $packet->authTag = $encrypted['tag'];
        
        $this->sendPacket($packet);
    }

    public function disconnect()
    {
        $packet = new Packet(Protocol::MSG_DISCONNECT, "", $this->sessionId);
        $this->sendPacket($packet);
        if ($this->socket) {
            socket_close($this->socket);
        }
    }

    private function sendPacket(Packet $packet)
    {
        // echo "[DEBUG] Sending Packet Type: " . dechex($packet->header->msgType) . "\n";
        $bin = Packet::encode($packet);
        socket_write($this->socket, $bin, strlen($bin));
    }

    public function readPacket(): Packet
    {
        // Read Header (45 bytes)
        $headerBin = socket_read($this->socket, 45);
        if ($headerBin === false || strlen($headerBin) < 45) {
            throw new \Exception("Failed to read header");
        }
        
        // Peek length (offset 7, 4 bytes, V = uint32 LE)
        $length = unpack('V', substr($headerBin, 7, 4))[1];
        
        // Peek flags (offset 5, 2 bytes, v = uint16 LE)
        $flags = unpack('v', substr($headerBin, 5, 2))[1];
        
        $extra = ($flags & Protocol::FLAG_ENCRYPTED) ? 16 : 0;
        $totalToRead = $length + $extra;
        
        $payloadBin = "";
        if ($totalToRead > 0) {
            $payloadBin = socket_read($this->socket, $totalToRead);
            if (strlen($payloadBin) < $totalToRead) {
                 throw new \Exception("Incomplete payload");
            }
        }
        
        return Packet::decode($headerBin . $payloadBin);
    }

    public function getSocket()
    {
        return $this->socket;
    }

    public function authenticate(string $username, string $password)
    {
        if (!$this->cryptoSession) {
            throw new \Exception("No secure session");
        }

        $payload = json_encode(['username' => $username, 'password' => $password]);
        $enc = $this->cryptoSession->encrypt($payload);

        $packet = new Packet(Protocol::MSG_AUTH_REQUEST, $enc['ciphertext'], $this->sessionId);
        $packet->header->flags |= Protocol::FLAG_ENCRYPTED;
        $packet->header->sequence = $enc['sequence'];
        $packet->authTag = $enc['tag'];

        $this->sendPacket($packet);

        // Wait for response
        $response = $this->readPacket();
        
        if (($response->header->flags & Protocol::FLAG_ENCRYPTED) && $this->cryptoSession) {
            $decrypted = $this->decryptPacket($response);
            
            if ($response->header->msgType === Protocol::MSG_AUTH_SUCCESS) {
                echo "Auth Success: " . $decrypted . "\n";
                return;
            } else if ($response->header->msgType === Protocol::MSG_AUTH_FAILURE) {
                throw new \Exception("Auth Failed: " . $decrypted);
            }
        }
        
        if ($response->header->msgType === Protocol::MSG_AUTH_FAILURE) {
             throw new \Exception("Auth Failed");
        }

        throw new \Exception("Unexpected packet during auth: " . $response->header->msgType);
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
        
        // Init
        $initData = json_encode([
            'id' => $fileId,
            'filename' => $filename,
            'size' => $size
        ]);
        $this->sendEncryptedPacket(Protocol::MSG_FILE_INIT, $initData);
        
        echo "Sending file $filename ($size bytes)...\n";
        
        // Chunks
        $handle = fopen($filePath, "rb");
        if ($handle === false) throw new \Exception("Cannot open file");
        
        while (!feof($handle)) {
            $chunk = fread($handle, 16384);
            if ($chunk === false || strlen($chunk) === 0) break;
            
            $payload = $fileIdBytes . $chunk;
            $this->sendEncryptedPacket(Protocol::MSG_FILE_CHUNK, $payload);
        }
        fclose($handle);
        
        // Complete
        $this->sendEncryptedPacket(Protocol::MSG_FILE_COMPLETE, $fileIdBytes);
        echo "File sent.\n";
    }

    private function sendEncryptedPacket(int $type, string $payload)
    {
        if (!$this->cryptoSession) return;
        
        $enc = $this->cryptoSession->encrypt($payload);
        $packet = new Packet($type, $enc['ciphertext'], $this->sessionId);
        $packet->header->flags |= Protocol::FLAG_ENCRYPTED;
        $packet->header->sequence = $enc['sequence'];
        $packet->authTag = $enc['tag'];
        
        $this->sendPacket($packet);
    }

    public function close()
    {
        if ($this->socket) {
            socket_close($this->socket);
        }
    }
}
