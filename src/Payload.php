<?php

declare(strict_types=1);

namespace AltchaOrg\Altcha;

class Payload
{
    public string $algorithm;
    public string $challenge;
    public int $number;
    public string $salt;
    public string $signature;

    public function __construct(string $algorithm, string $challenge, int $number, string $salt, string $signature)
    {
        $this->algorithm = $algorithm;
        $this->challenge = $challenge;
        $this->number = $number;
        $this->salt = $salt;
        $this->signature = $signature;
    }
}
