<?php

require 'vendor/autoload.php';

use AdaTP\Client;

echo "Starting AdaTP PHP Client...\n";

try {
    $client = new Client('127.0.0.1', 3000);
    
    echo "Connecting...\n";
    $client->connect();
    
    echo "Sending Message...\n";
    $client->sendTextMessage("Hello from PHP!");
    
    echo "Disconnecting...\n";
    $client->disconnect();
    
} catch (\Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
