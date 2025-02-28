<?php

declare(strict_types=1);

namespace AltchaOrg\Altcha;

class ServerSignatureVerificationData
{
    public string $classification;
    public string $country;
    public string $detectedLanguage;
    public string $email;
    public int $expire;
    public array $fields;
    public string $fieldsHash;
    public array $reasons;
    public float $score;
    public int $time;
    public bool $verified;
}
