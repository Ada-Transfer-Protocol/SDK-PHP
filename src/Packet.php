<?php

namespace AdaTP;

use Ramsey\Uuid\Uuid;

class Packet
{
    public $header;
    public $payload;
    public $authTag;

    public function __construct(int $msgType, string $payload, ?string $sessionId = null)
    {
        $this->header = new PacketHeader();
        $this->header->msgType = $msgType;
        $this->header->length = strlen($payload);
        
        // Default SessionID (Nil UUID)
        $this->header->sessionId = $sessionId ?? Uuid::nil()->getBytes();
        
        $this->payload = $payload;
        $this->authTag = null;
    }

    public static function encode(Packet $packet): string
    {
        // Magic (4) LE
        $bin = pack('V', $packet->header->magic);
        // Version (1)
        $bin .= pack('C', $packet->header->version);
        // Flags (2) LE
        $bin .= pack('v', $packet->header->flags);
        // Length (4) LE
        $bin .= pack('V', strlen($packet->payload)); // Update length dynamically
        // Sequence (8) LE (64-bit)
        $bin .= pack('P', $packet->header->sequence);
        // MsgType (2) LE
        $bin .= pack('v', $packet->header->msgType);
        // Timestamp (8) LE
        $bin .= pack('P', $packet->header->timestamp);
        // SessionID (16) raw bytes
        // Ensure session ID is 16 bytes
        $sessId = $packet->header->sessionId;
        if (strlen($sessId) !== 16) {
             $sessId = str_repeat("\0", 16);
        }
        $bin .= $sessId;

        // Payload
        $bin .= $packet->payload;

        // Auth Tag
        if ($packet->authTag !== null) {
            $bin .= $packet->authTag;
        }

        return $bin;
    }

    public static function decode(string $buffer): Packet
    {
        // We assume buffer contains at least header.
        // Unpack header
        // V: uint32 LE, C: uint8, v: uint16 LE, P: uint64 LE
        
        $magic = unpack('V', substr($buffer, 0, 4))[1];
        $version = unpack('C', substr($buffer, 4, 1))[1];
        $flags = unpack('v', substr($buffer, 5, 2))[1];
        $length = unpack('V', substr($buffer, 7, 4))[1];
        $sequence = unpack('P', substr($buffer, 11, 8))[1];
        $msgType = unpack('v', substr($buffer, 19, 2))[1];
        $timestamp = unpack('P', substr($buffer, 21, 8))[1];
        $sessionId = substr($buffer, 29, 16);

        $payload = substr($buffer, 45, $length);
        
        $authTag = null;
        if ($flags & Protocol::FLAG_ENCRYPTED) {
            $authTag = substr($buffer, 45 + $length, 16);
        }

        // Reconstruct Packet
        $p = new Packet($msgType, $payload, $sessionId);
        $p->header->magic = $magic;
        $p->header->version = $version;
        $p->header->flags = $flags;
        $p->header->length = $length;
        $p->header->sequence = $sequence;
        $p->header->timestamp = $timestamp;
        $p->authTag = $authTag;

        return $p;
    }
}

class PacketHeader
{
    public $magic = 0x41444154;
    public $version = 1;
    public $flags = 0;
    public $length = 0;
    public $sequence = 0;
    public $msgType = 0;
    public $timestamp = 0;
    public $sessionId;

    public function __construct() {
        $this->timestamp = time() * 1000;
    }
}
