<?php

namespace VaasSdk\Message;

class ProblemDetails
{
    public string $type;

    public string $detail;

    /**
     * @return string
     */
    public function getDetail(): string
    {
        return $this->detail;
    }

    /**
     * @return string
     */
    public function getType(): string
    {
        return $this->type;
    }
}