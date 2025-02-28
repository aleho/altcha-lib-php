<?php

declare(strict_types=1);

namespace AltchaOrg\Altcha;

class ChallengeOptions
{
    public string $algorithm;
    public float $maxNumber;
    public int $saltLength;
    public string $hmacKey;
    public string $salt;
    public int $number;
    public ?int $expires;

    /** @var array<array-key, null|scalar> */
    public array $params;

    public function __construct($options = [])
    {
        $this->algorithm = $options['algorithm'] ?? Altcha::DEFAULT_ALGORITHM;
        $this->maxNumber = $options['maxNumber'] ?? Altcha::DEFAULT_MAX_NUMBER;
        $this->saltLength = $options['saltLength'] ?? Altcha::DEFAULT_SALT_LENGTH;
        $this->hmacKey = $options['hmacKey'] ?? '';
        $this->salt = $options['salt'] ?? '';
        $this->number = $options['number'] ?? 0;
        $this->expires = $options['expires'] ?? null;
        $this->params = $options['params'] ?? [];
    }
}
