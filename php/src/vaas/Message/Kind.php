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
    public const VERDICT_REQUEST_FOR_URL = "VerdictRequestForUrl";
    public const ERROR = "Error";

    private string $_kindString = "";

    public function __construct(string $type)
    {
        switch ($type) {
            case self::AUTH_REQUEST:
                $this->_kindString = self::AUTH_REQUEST;
                break;
            case self::AUTH_RESPONSE:
                $this->_kindString = self::AUTH_RESPONSE;
                break;
            case self::VERDICT_REQUEST:
                $this->_kindString = self::VERDICT_REQUEST;
                break;
            case self::VERDICT_RESPONSE:
                $this->_kindString = self::VERDICT_RESPONSE;
                break;
            case self::VERDICT_REQUEST_FOR_URL:
                $this->_kindString = self::VERDICT_REQUEST_FOR_URL;
                break;
            case self::ERROR:
                $this->_kindString = self::ERROR;
                break;
            default:
                throw new UnknownKindException();
        }
    }

    public function __toString()
    {
        return $this->_kindString;
    }

    public function jsonSerialize(): string
    {
        return $this->_kindString;
    }
}
