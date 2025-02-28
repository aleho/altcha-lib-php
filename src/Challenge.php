<?php

declare(strict_types=1);

namespace AltchaOrg\Altcha;

class Challenge
{
    public function __construct(
        public readonly string $algorithm,
        public readonly string $challenge,
        public readonly int $maxnumber,
        public readonly string $salt,
        public readonly string $signature,
    ) {
    }
}
