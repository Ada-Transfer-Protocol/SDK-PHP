<?php

namespace AdaTP\Crypto;

/** A v2 handshake failure carrying a stable, machine-readable string code. */
class AdaTPHandshakeException extends \Exception
{
    /** e.g. "unknown_identity", "signature_verification_failed". */
    public $errorCode;

    public function __construct(string $errorCode, string $message)
    {
        parent::__construct($message);
        $this->errorCode = $errorCode;
    }
}
