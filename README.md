# AdaTP PHP SDK

A modern, PSR-compliant PHP client library for the **Ada Transfer Protocol (AdaTP)**. This SDK provides easy-to-use abstractions for creating secure, real-time PHP applications (CLI tools, daemons, etc.).

## 📦 Features
*   **Cryptography:** Uses `ext-openssl` for AES-256-GCM and X25519 key exchange.
*   **WebSocket Transport:** Dependency-free RFC 6455 client built on PHP streams (ws:// and wss://).
*   **Compatibility:** Works with PHP 8.0+.

## 🚀 Installation

Ensure you have `composer` installed.

```bash
composer install
```

**Requirements:**
*   PHP 8.0+

*   `ext-openssl`

## 🛠️ Usage

### 1. Basic Chat Client

```php
<?php
require 'vendor/autoload.php';

use AdaTP\Client;
use AdaTP\Protocol;

try {
    // 1. Initialize & Connect
    $client = new Client('127.0.0.1', 3000);
    $client->connect(); // Handshake

    // 2. Authenticate
    $client->authenticate("myuser", "mypass");
    
    // 3. Join Room
    $client->joinRoom("general");

    // 4. Send Message
    $client->sendTextMessage("Hello from PHP!");

    // 5. Receive One Packet
    $packet = $client->readPacket();
    if ($packet->header->msgType === Protocol::MSG_TEXT_MESSAGE) {
        $text = $client->decryptPacket($packet);
        echo "Received: $text\n";
    }

} catch (Exception $e) {
    echo "Error: " . $e->getMessage();
}
```

### 2. File Transfer

The SDK calculates all necessary headers and checksums for you.

**Sending a File:**
```php
$client->sendFile("/path/to/image.png");
```

**Receiving:**
As PHP is typically synchronous, handling file downloads usually requires a while-loop listening for `MSG_FILE_INIT`, `MSG_FILE_CHUNK`, and `MSG_FILE_COMPLETE`. 

See `filetransfer_example.php` for a robust implementation that saves incoming streams to disk.

### 3. Authenticated handshake (protocol v2)

By default the client runs the v1 (unauthenticated) handshake, which relies on
TLS for server authentication. Pinning the server's long-term Ed25519 identity
switches to **protocol v2**: the client verifies the server's signature over the
handshake transcript (and binds the frame header as AEAD AAD) **before** deriving
any key, defeating an active man-in-the-middle even without TLS.

```php
// The server's 32-byte Ed25519 public key (hex), obtained out of band. The
// server logs its fingerprint at startup.
$client = new Client('127.0.0.1', 3000, '/ws', false, 'en',
                     'd04ab232...c9778737');   // <-- enables v2 + pinning
$client->connect();   // authenticated handshake; throws AdaTPHandshakeException on a bad key/signature
```

Verified against the Rust reference server end to end (`test/run_e2e_v2.sh`) and
by golden-vector conformance (`test/conformance_v2.php`, run in CI). Require v2
server-side with `ADATP_MIN_PROTOCOL_VERSION=2`.

## 📂 Examples

*   **Chat CLI:** `php chat-example.php`
    *   An interactive CLI chat client. Uses `stream_select` to handle user input (STDIN) and network packets simultaneously without blocking.
*   **File Transfer:** `php filetransfer_example.php`
    *   Connects as a bot, sends a generated text file, and listens for incoming file transfers.

## 🔧 Configuration

The client constructor accepts the host IP and port:
```php
$client = new Client('192.168.1.5', 3000);
```

## Language / locale

The client takes a `$locale` constructor argument for its user-facing
strings (client-side metadata — the wire protocol is language-neutral).
Default `en`; supported: `en tr it fr de zh ja hi ar`.

```php
$client = new Client('127.0.0.1', 3000, '/ws', false, 'tr');
$client->setLocale('de'); // switch at runtime
```
