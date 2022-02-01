<?php

namespace VaasSdk\Message;

use VaasSdk\Exceptions\UnkownVerdictException;
use JsonSerializable;

class Verdict implements JsonSerializable
{
    public const MALICIOUS = "Malicious";
    public const CLEAN = "Clean";
    public const UNKNOWN = "Unknown";

    private string $verdictString = "";

    public function __construct(string $type)
    {
        switch ($type) {
            case Verdict::MALICIOUS:
                $this->verdictString = Verdict::MALICIOUS;
                break;
            case self::CLEAN:
                $this->verdictString = Verdict::CLEAN;
                break;
            case self::UNKNOWN:
                $this->verdictString = Verdict::UNKNOWN;
                break;
            default:
                throw new UnkownVerdictException();
        }
    }

    public function __toString()
    {
        return $this->verdictString;
    }

    public function jsonSerialize()
    {
        return $this->verdictString;
    }
}
