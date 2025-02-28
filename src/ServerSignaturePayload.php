<?php

declare(strict_types=1);

namespace AltchaOrg\Altcha;

class ServerSignaturePayload
{
    public string $algorithm;
    public string $verificationData;
    public string $signature;
    public bool $verified;

    public function __construct(string $algorithm, string $verificationData, string $signature, bool $verified)
    {
        $this->algorithm = $algorithm;
        $this->verificationData = $verificationData;
        $this->signature = $signature;
        $this->verified = $verified;
    }
}
