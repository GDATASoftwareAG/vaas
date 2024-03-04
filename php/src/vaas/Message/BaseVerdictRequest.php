<?php

namespace VaasSdk\Message;

use Ramsey\Uuid\Rfc4122\UuidV4;

class BaseVerdictRequest extends BaseMessage
{
    public string $guid;
    public string $session_id;
    public bool $UseHashLookup;
    public bool $UseCache;

    public function __construct(kind $kind, string $uuid = null, string $SessionId)
    {
        $this->kind = $kind;
        $this->guid = $uuid != null ? $uuid : UuidV4::getFactory()->uuid4()->toString();
        $this->session_id = $SessionId;
    }
}
