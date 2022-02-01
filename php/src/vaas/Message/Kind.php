<?php

namespace VaasSdk\Message;

use JsonSerializable;
use VaasSdk\Exceptions\UnknownKindException;

class Kind implements JsonSerializable
{
    public const AUTH_REQUEST = "AuthRequest";
    public const AUTH_RESPONSE = "AuthResponse";
    public const VERDICT_REQUEST = "VerdictRequest";
    public const VERDICT_RESPONSE = "VerdictResponse";

    private string $kindString = "";

    public function __construct(string $type)
    {
        switch ($type) {
            case self::AUTH_REQUEST:
                $this->kindString = self::AUTH_REQUEST;
                break;
            case self::AUTH_RESPONSE:
                $this->kindString = self::AUTH_RESPONSE;
                break;
            case self::VERDICT_REQUEST:
                $this->kindString = self::VERDICT_REQUEST;
                break;
            case self::VERDICT_RESPONSE:
                $this->kindString = self::VERDICT_RESPONSE;
                break;                
            default:
                throw new UnknownKindException();
        }
    }

    public function __toString()
    {
        return $this->kindString;
    }

    public function jsonSerialize()
    {
        return $this->kindString;
    }
}

