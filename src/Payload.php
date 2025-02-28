<?php

declare(strict_types=1);

namespace AltchaOrg\Altcha;

use AltchaOrg\Altcha\Hasher\Algorithm;

class Payload
{
    public Algorithm $algorithm;
    public string $challenge;
    public int $number;
    public string $salt;
    public string $signature;

    public function __construct(Algorithm $algorithm, string $challenge, int $number, string $salt, string $signature)
    {
        $this->algorithm = $algorithm;
        $this->challenge = $challenge;
        $this->number = $number;
        $this->salt = $salt;
        $this->signature = $signature;
    }
}
