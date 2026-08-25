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

    /**
     * The 45-byte header, serialized as on the wire. Also used as the AEAD AAD
     * in protocol v2, so it must match the server's PacketHeader::header_bytes()
     * byte-for-byte.
     */
    public static function headerBytes(PacketHeader $h): string
    {
        $sessId = $h->sessionId;
        if (strlen($sessId) !== 16) {
            $sessId = str_repeat("\0", 16);
        }
        return pack('V', $h->magic)         // magic (4) LE
             . pack('C', $h->version)       // version (1)
             . pack('v', $h->flags)         // flags (2) LE
             . pack('V', $h->length)        // length (4) LE
             . pack('P', $h->sequence)      // sequence (8) LE
             . pack('v', $h->msgType)       // msgType (2) LE
             . pack('P', $h->timestamp)     // timestamp (8) LE
             . $sessId;                      // sessionId (16)
    }

    public static function encode(Packet $packet): string
    {
        // Length is the payload length on the wire.
        $packet->header->length = strlen($packet->payload);
        $bin = self::headerBytes($packet->header);
        $bin .= $packet->payload;
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
