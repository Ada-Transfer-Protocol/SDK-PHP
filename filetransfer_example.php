<?php

require 'vendor/autoload.php';

use AdaTP\Client;
use AdaTP\Packet;
use AdaTP\Protocol;
use Ramsey\Uuid\Uuid;

if (php_sapi_name() !== 'cli') die("CLI only\n");

echo "PHP File Transfer Example\n";

$downloadDir = __DIR__ . '/downloads_php';
if (!is_dir($downloadDir)) mkdir($downloadDir);

// Dummy file
$uploadFile = __DIR__ . '/upload_test_php.txt';
file_put_contents($uploadFile, str_repeat("PHP File Transfer Test\n", 50));

try {
    $client = new Client('127.0.0.1', 8444);
    $client->connect();
    $client->authenticate('phpbot', 'secret_password');
    
    // Join Room
    echo "Joining 'files' room...\n";
    // Assuming joinRoom exists as per chat-example
    if (method_exists($client, 'joinRoom')) {
        $client->joinRoom('files');
    } else {
        echo "Warning: joinRoom method not found, skipping room join.\n";
    }
    
    echo "Sending file in 2 seconds...\n";
    sleep(2);
    $client->sendFile($uploadFile);
    
    echo "Listening for files...\n";
    $socket = $client->getSocket();
    $activeFiles = []; // id => [handle, path, total]

    while (true) {
        $pkt = $client->readPacket();
        
        if ($pkt->header->flags & Protocol::FLAG_ENCRYPTED) {
            $decrypted = $client->decryptPacket($pkt);
            
            if ($pkt->header->msgType === Protocol::MSG_FILE_INIT) {
                $meta = json_decode($decrypted, true);
                if ($meta) {
                    $fid = $meta['id'];
                    $fname = $meta['filename'];
                    $sender = $meta['sender'] ?? 'unknown';
                    $size = $meta['size'];
                    
                    echo "Receiving $fname from $sender (Size: $size)\n";
                    $savePath = $downloadDir . '/' . $sender . '_' . $fname;
                    $handle = fopen($savePath, 'wb');
                    $activeFiles[$fid] = ['handle' => $handle, 'path' => $savePath, 'total' => 0];
                }
            } elseif ($pkt->header->msgType === Protocol::MSG_FILE_CHUNK) {
                if (strlen($decrypted) > 16) {
                    $fidBytes = substr($decrypted, 0, 16);
                    $data = substr($decrypted, 16);
                    $fid = Uuid::fromBytes($fidBytes)->toString();
                    
                    if (isset($activeFiles[$fid])) {
                        fwrite($activeFiles[$fid]['handle'], $data);
                        $activeFiles[$fid]['total'] += strlen($data);
                        echo ".";
                    }
                }
            } elseif ($pkt->header->msgType === Protocol::MSG_FILE_COMPLETE) {
                $fidBytes = substr($decrypted, 0, 16);
                $fid = Uuid::fromBytes($fidBytes)->toString();
                
                if (isset($activeFiles[$fid])) {
                    fclose($activeFiles[$fid]['handle']);
                    echo "\nDownload Complete: " . $activeFiles[$fid]['path'] . "\n";
                    unset($activeFiles[$fid]);
                }
            } elseif ($pkt->header->msgType === Protocol::MSG_TEXT_MESSAGE) {
                echo "Chat: $decrypted\n";
            }
        }
    }

} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
