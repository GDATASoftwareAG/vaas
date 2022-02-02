<?php

namespace VaasSdk\Message;

use VaasSdk\Exceptions\UnkownVerdictException;
use JsonSerializable;

class Verdict implements JsonSerializable
{
    public const MALICIOUS = "Malicious";
    public const CLEAN = "Clean";
    public const UNKNOWN = "Unknown";

    private string $_verdictString = "";

    public function __construct(string $type)
    {
        switch ($type) {
            case Verdict::MALICIOUS:
                $this->_verdictString = Verdict::MALICIOUS;
                break;
            case self::CLEAN:
                $this->_verdictString = Verdict::CLEAN;
                break;
            case self::UNKNOWN:
                $this->_verdictString = Verdict::UNKNOWN;
                break;
            default:
                throw new UnkownVerdictException();
        }
    }

    public function __toString()
    {
        return $this->_verdictString;
    }

    public function jsonSerialize()
    {
        return $this->_verdictString;
    }
}
