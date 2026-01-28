<?php

require 'vendor/autoload.php';

use AdaTP\Client;
use AdaTP\Packet;
use AdaTP\Protocol;

// Check if run from CLI
if (php_sapi_name() !== 'cli') {
    die("This script must be run from the command line.\n");
}

echo "==========================================\n";
echo "   AdaTP PHP Chat Client (CLI Version)    \n";
echo "==========================================\n";

// 1. Get Username
echo "Enter your username: ";
$handle = fopen("php://stdin", "r");
$username = trim(fgets($handle));
if (empty($username)) {
    $username = "Anonymous";
}

echo "Enter password (default: secret_password): ";
$password = trim(fgets($handle));
if (empty($password)) $password = "secret_password";

try {
    // 2. Connect
    echo "Connecting to localhost:8444...\n";
    $client = new Client('127.0.0.1', 8444);
    $client->connect(); // Handshake
    
    echo "Authenticating...\n";
    $client->authenticate($username, $password);
    
    echo "Joined chat as '$username'. Type messages and press Enter.\n";
    echo "Type '/quit' to exit.\n\n";

    // Prepare for loop
    $socket = $client->getSocket();
    
    // Set socket to non-blocking so we can interleave with STDIN
    socket_set_nonblock($socket);
    stream_set_blocking(STDIN, 0);

    // Initial Join Message
    // In a real app we might use PRESENCE_UPDATE or just text
    $client->sendTextMessage("👋 $username joined the chat!");

    while (true) {
        // --- 1. Handle STDIN (User Input) ---
        $readStreams = [STDIN];
        $writeStreams = $exceptStreams = null;
        
        // stream_select returns number of streams with data
        // We use a small timeout to not block too long, but allow CPU to rest
        if (stream_select($readStreams, $writeStreams, $exceptStreams, 0, 10000) > 0) {
            $line = trim(fgets(STDIN));
            if (!empty($line)) {
                if ($line === '/quit') {
                    echo "Exiting...\n";
                    break;
                }
                
                if (strpos($line, '/join ') === 0) {
                    $room = substr($line, 6);
                    $client->joinRoom($room);
                    echo "Joined room: $room\n";
                    continue;
                }
                
                // Format: [Username] Message
                $msg = "[$username] $line";
                
                // Must temporarily set blocking for send to ensure full write? 
                // sendTextMessage calls sendPacket calls socket_write which blocks usually.
                // But we set socket to nonblock. socket_write might return partial or EAGAIN.
                // Our simple SDK assumes blocking writes. Let's toggle or handle retry.
                // For this example, let's assume small payload fits in buffer.
                socket_set_block($socket);
                $client->sendTextMessage($msg);
                socket_set_nonblock($socket);
                
                // Move cursor up logic? Or just print "Sent"
                // echo "\033[1A"; // Ansi up
            }
        }

        // --- 2. Handle Socket (Incoming Messages) ---
        $readSocks = [$socket];
        $writeSocks = $exceptSocks = null;
        
        // socket_select for ext-sockets
        if (socket_select($readSocks, $writeSocks, $exceptSocks, 0, 10000) > 0) {
            // Data available!
            // We need to read packet.
            // Be careful because readPacket in Client.php is designed for Blocking IO.
            // calling it on non-blocking socket might assume full header is there but it might not be.
            
            // Hack for demo: Temporarily set blocking to read one full packet reliably
            socket_set_block($socket);
            try {
                $pkt = $client->readPacket();
                
                if ($pkt->header->msgType === Protocol::MSG_TEXT_MESSAGE) {
                    $text = $client->decryptPacket($pkt);
                    // Clear current line if user was typing? 
                    // "\r\x1b[K" clears line.
                    echo "\r\x1b[K"; // Clear "Type message" prompt if any
                    echo "< $text\n";
                    echo "> "; // Reprint prompt
                    // Flush output
                    if (ob_get_level() > 0) ob_flush();
                } else if ($pkt->header->msgType === Protocol::MSG_DISCONNECT) {
                    echo "\nServer Disconnected.\n";
                    break;
                }
            } catch (Exception $e) {
                echo "Socket Error: " . $e->getMessage() . "\n";
                break;
            }
            socket_set_nonblock($socket);
        }
        
        // Wait a tiny bit (10ms) to reduce CPU usage
        usleep(10000);
    }
    
    $client->disconnect();

} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
