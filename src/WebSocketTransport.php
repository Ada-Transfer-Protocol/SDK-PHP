<?php

namespace AdaTP;

/**
 * Minimal RFC 6455 WebSocket client used as the AdaTP transport.
 *
 * Dependency-free (PHP streams only). Supports ws:// and wss://, binary
 * messages, ping/pong, and server-initiated close. Fragmented messages are
 * reassembled. Client frames are masked as the RFC requires.
 */
class WebSocketTransport
{
    private $stream;
    private $connected = false;

    /**
     * @param string $url e.g. "ws://127.0.0.1:3000/ws" or "wss://host/ws"
     */
    public function connect(string $url, float $timeout = 10.0): void
    {
        $parts = parse_url($url);
        if ($parts === false || !isset($parts['scheme'], $parts['host'])) {
            throw new \Exception("Invalid WebSocket URL: $url");
        }

        $secure = $parts['scheme'] === 'wss';
        $host = $parts['host'];
        $port = $parts['port'] ?? ($secure ? 443 : 80);
        $path = ($parts['path'] ?? '/') . (isset($parts['query']) ? '?' . $parts['query'] : '');

        $remote = ($secure ? 'ssl://' : 'tcp://') . $host . ':' . $port;
        $errno = 0;
        $errstr = '';
        $this->stream = stream_socket_client($remote, $errno, $errstr, $timeout);
        if ($this->stream === false) {
            throw new \Exception("Connection to $remote failed: [$errno] $errstr");
        }
        stream_set_timeout($this->stream, (int)$timeout);

        // HTTP Upgrade handshake
        $key = base64_encode(random_bytes(16));
        $headers = "GET $path HTTP/1.1\r\n"
            . "Host: $host:$port\r\n"
            . "Upgrade: websocket\r\n"
            . "Connection: Upgrade\r\n"
            . "Sec-WebSocket-Key: $key\r\n"
            . "Sec-WebSocket-Version: 13\r\n"
            . "\r\n";
        fwrite($this->stream, $headers);

        $response = '';
        while (strpos($response, "\r\n\r\n") === false) {
            $chunk = fread($this->stream, 1024);
            if ($chunk === false || $chunk === '') {
                throw new \Exception("WebSocket handshake failed: no response");
            }
            $response .= $chunk;
            if (strlen($response) > 16384) {
                throw new \Exception("WebSocket handshake failed: oversized response");
            }
        }

        if (strpos($response, ' 101 ') === false) {
            throw new \Exception("WebSocket handshake failed: " . strtok($response, "\r\n"));
        }

        $expected = base64_encode(sha1($key . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11', true));
        if (!preg_match('/Sec-WebSocket-Accept:\s*(\S+)/i', $response, $m) || trim($m[1]) !== $expected) {
            throw new \Exception("WebSocket handshake failed: bad Sec-WebSocket-Accept");
        }

        // Any bytes after the header block are the first frames.
        $extra = substr($response, strpos($response, "\r\n\r\n") + 4);
        $this->rxBuffer = $extra !== false ? $extra : '';
        $this->connected = true;
    }

    private $rxBuffer = '';

    public function isConnected(): bool
    {
        return $this->connected;
    }

    /** Underlying PHP stream (usable with stream_select). */
    public function getStream()
    {
        return $this->stream;
    }

    /** True if bytes are already buffered (stream_select would not see them). */
    public function hasBuffered(): bool
    {
        return $this->rxBuffer !== '';
    }

    /** Sends one binary WebSocket message. */
    public function sendBinary(string $payload): void
    {
        $this->sendFrame(0x2, $payload);
    }

    /**
     * Receives the next complete binary message (reassembling fragments).
     * Ping frames are answered transparently. Returns null on clean close.
     */
    public function recvBinary(): ?string
    {
        $message = '';
        $receivingBinary = false;

        while (true) {
            $frame = $this->readFrame();
            if ($frame === null) {
                return null;
            }
            [$opcode, $fin, $payload] = $frame;

            switch ($opcode) {
                case 0x2: // binary
                    $message = $payload;
                    $receivingBinary = true;
                    if ($fin) return $message;
                    break;
                case 0x0: // continuation
                    if ($receivingBinary) {
                        $message .= $payload;
                        if ($fin) return $message;
                    }
                    break;
                case 0x1: // text — AdaTP is binary-only; ignore
                    break;
                case 0x9: // ping → pong
                    $this->sendFrame(0xA, $payload);
                    break;
                case 0xA: // pong
                    break;
                case 0x8: // close
                    $this->sendFrame(0x8, '');
                    $this->close(false);
                    return null;
            }
        }
    }

    public function close(bool $sendCloseFrame = true): void
    {
        if ($this->stream) {
            if ($sendCloseFrame && $this->connected) {
                @$this->sendFrame(0x8, '');
            }
            @fclose($this->stream);
            $this->stream = null;
        }
        $this->connected = false;
    }

    // ------------------------------------------------------------------

    private function sendFrame(int $opcode, string $payload): void
    {
        $len = strlen($payload);
        $header = chr(0x80 | $opcode); // FIN + opcode

        if ($len < 126) {
            $header .= chr(0x80 | $len); // MASK bit + length
        } elseif ($len < 65536) {
            $header .= chr(0x80 | 126) . pack('n', $len);
        } else {
            $header .= chr(0x80 | 127) . pack('J', $len);
        }

        $mask = random_bytes(4);
        $header .= $mask;

        $masked = $payload;
        for ($i = 0; $i < $len; $i++) {
            $masked[$i] = $payload[$i] ^ $mask[$i % 4];
        }

        $this->writeAll($header . $masked);
    }

    /** @return array{0:int,1:bool,2:string}|null [opcode, fin, payload] */
    private function readFrame(): ?array
    {
        $head = $this->readExact(2);
        if ($head === null) return null;

        $b1 = ord($head[0]);
        $b2 = ord($head[1]);
        $fin = ($b1 & 0x80) !== 0;
        $opcode = $b1 & 0x0F;
        $masked = ($b2 & 0x80) !== 0;
        $len = $b2 & 0x7F;

        if ($len === 126) {
            $ext = $this->readExact(2);
            if ($ext === null) return null;
            $len = unpack('n', $ext)[1];
        } elseif ($len === 127) {
            $ext = $this->readExact(8);
            if ($ext === null) return null;
            $len = unpack('J', $ext)[1];
        }

        $maskKey = '';
        if ($masked) { // servers do not mask, but tolerate it
            $maskKey = $this->readExact(4);
            if ($maskKey === null) return null;
        }

        $payload = $len > 0 ? $this->readExact($len) : '';
        if ($payload === null) return null;

        if ($masked) {
            for ($i = 0; $i < $len; $i++) {
                $payload[$i] = $payload[$i] ^ $maskKey[$i % 4];
            }
        }

        return [$opcode, $fin, $payload];
    }

    private function readExact(int $n): ?string
    {
        while (strlen($this->rxBuffer) < $n) {
            $chunk = fread($this->stream, max(1, $n - strlen($this->rxBuffer)));
            if ($chunk === false || $chunk === '') {
                $meta = stream_get_meta_data($this->stream);
                if ($meta['timed_out']) {
                    throw new \Exception("WebSocket read timeout");
                }
                return null; // connection closed
            }
            $this->rxBuffer .= $chunk;
        }
        $out = substr($this->rxBuffer, 0, $n);
        $this->rxBuffer = substr($this->rxBuffer, $n);
        return $out;
    }

    private function writeAll(string $data): void
    {
        $total = strlen($data);
        $written = 0;
        while ($written < $total) {
            $n = fwrite($this->stream, substr($data, $written));
            if ($n === false || $n === 0) {
                throw new \Exception("WebSocket write failed");
            }
            $written += $n;
        }
    }
}
