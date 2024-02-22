<?php

namespace VaasSdk\Message;

class Error extends BaseMessage
{
    public string $type;

    public string $requestId;

    public string $text;

    public ?ProblemDetails $problem_details;

    public function __construct()
    {
        $this->kind = Kind::Error;
    }

    /**
     * @return string
     */
    public function getType(): string
    {
        return $this->type;
    }

    /**
     * @return Kind
     */
    public function getKind(): Kind
    {
        return $this->kind;
    }

    /**
     * @return ProblemDetails
     */
    public function getProblemDetails(): ProblemDetails
    {
        return $this->problem_details;
    }

    /**
     * @return string
     */
    public function getRequestId(): string
    {
        return $this->requestId;
    }

    /**
     * @return string
     */
    public function getText(): string
    {
        return $this->text;
    }
}
