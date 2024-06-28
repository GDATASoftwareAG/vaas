<?php

namespace VaasSdk\Message;

use Ramsey\Uuid\Rfc4122\UuidV4;

class BaseVerdictRequest extends BaseMessage
{
    public string $guid;
    public ?string $session_id = null;
    public bool $use_hash_lookup;
    public bool $use_cache;

    public function __construct(kind $kind, string $uuid = null)
    {
        $this->kind = $kind;
        $this->guid = $uuid != null ? $uuid : UuidV4::getFactory()->uuid4()->toString();
    }
}
