<?php

declare(strict_types=1);

namespace AltchaOrg\Altcha;

class Challenge
{
    public string $algorithm;
    public string $challenge;
    public float $maxnumber;
    public string $salt;
    public string $signature;

    public function __construct(string $algorithm, string $challenge, float $maxNumber, string $salt, string $signature)
    {
        $this->algorithm = $algorithm;
        $this->challenge = $challenge;
        $this->maxnumber = $maxNumber;
        $this->salt = $salt;
        $this->signature = $signature;
    }
}
