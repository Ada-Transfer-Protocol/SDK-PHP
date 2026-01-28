<?php

namespace AdaTP;

class Protocol
{
    const MAGIC_NUMBER = 0x41444154;
    const HEADER_SIZE = 45;

    const MSG_HANDSHAKE_INIT = 0x0001;
    const MSG_HANDSHAKE_RESPONSE = 0x0002;
    const MSG_HANDSHAKE_COMPLETE = 0x0003;

    // Auth
    const MSG_AUTH_REQUEST = 0x0010;
    const MSG_AUTH_SUCCESS = 0x0013;
    const MSG_AUTH_FAILURE = 0x0014;

    // Messaging
    const MSG_TEXT_MESSAGE = 0x0020;
    
    // File Transfer
    const MSG_FILE_INIT = 0x0030;
    const MSG_FILE_CHUNK = 0x0031;
    const MSG_FILE_ACK = 0x0032;
    const MSG_FILE_COMPLETE = 0x0033;
    const MSG_FILE_CANCEL = 0x0034;
    
    // Rooms
    const MSG_JOIN_ROOM = 0x00A0;
    const MSG_ROOM_JOINED = 0x00A1; // Not yet used by server but good to have

    const MSG_DISCONNECT = 0x00FF;

    const FLAG_ENCRYPTED = 0x0001;
    const FLAG_COMPRESSED = 0x0002;
    const FLAG_RELIABLE = 0x0004;
}
