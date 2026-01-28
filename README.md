# AdaTP PHP SDK

A robust, spec-compliant PHP client for the Ada Transport Protocol (AdaTP). This SDK supports both Native PHP and Laravel frameworks, providing secure, encrypted communication with AdaTP servers.

## Features

- **Secure Handshake**: Implements X25519 key exchange and HKDF key derivation (using `sodium` and `hash_hkdf`).
- **End-to-End Encryption**: AES-256-GCM encryption for all messages.
- **Laravel Integration**: Includes ServiceProvider, Facade, and Config publishing.
- **Protocol Compliant**: Fully compatible with the official AdaTP Rust server.

## Requirements

- PHP 7.4 or higher
- `ext-sockets`
- `ext-sodium`
- `ext-openssl`
- `ext-json`

## Installation

```bash
composer require adatp/php-sdk
# or locally
composer config repositories.adatp path ./path/to/adatp/sdks/php
composer require adatp/php-sdk @dev
```

## Usage

### Native PHP

```php
require 'vendor/autoload.php';

use AdaTP\Client;

try {
    // Connect to server
    $client = new Client('127.0.0.1', 8443);
    $client->connect(); // Performs Handshake automatically
    
    // Send secure message
    $client->sendTextMessage("Hello from PHP!");
    
    // Disconnect
    $client->disconnect();
    
} catch (Exception $e) {
    echo "Error: " . $e->getMessage();
}
```

### Laravel

1. **Register Service Provider** (if not auto-discovered):
   Add to `config/app.php`:
   ```php
   AdaTP\Providers\AdaTPServiceProvider::class,
   ```

2. **Publish Config**:
   ```bash
   php artisan vendor:publish --tag=adatp-config
   ```
   Edit `config/adatp.php` to set your server host and port.

3. **Use Facade**:
   ```php
   use AdaTP\Facades\AdaTP;

   public function sendMessage() {
       AdaTP::connect();
       AdaTP::sendTextMessage("Hello from Laravel Controller!");
       AdaTP::disconnect();
   }
   ```

## Protocol Support

| Feature | Status |
|---------|--------|
| Handshake (X25519) | ✅ |
| Encryption (AES-GCM) | ✅ |
| Text Messages | ✅ |
| Multi-Room Chat | ✅ |
| File Transfer | ✅ (Implemented) |
| Voice/Video | 🚧 (Planned) |

### Multi-Room Usage

```php
// Join a specific room
$client->joinRoom("devops");
$client->sendTextMessage("Hello DevOps team!");
```

## License

MIT
# SDK-PHP
