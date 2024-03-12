<?php

namespace VaasSdk\Message;

class Detection
{
    public ?int $engine;
    public string $fileName;
    public string $virus;

    public function getEngine(): int
    {
        return $this->engine;
    }

    public function setEngine(int $engine): void
    {
        $this->engine = $engine;
    }

    public function getFileName(): string
    {
        return $this->fileName;
    }

    public function setFileName(string $fileName): void
    {
        $this->fileName = $fileName;
    }

    public function getVirus(): string
    {
        return $this->virus;
    }

    public function setVirus(string $virus): void
    {
        $this->virus = $virus;
    }
}