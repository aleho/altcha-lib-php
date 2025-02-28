<?php

declare(strict_types=1);

namespace AltchaOrg\Altcha;

class Payload
{
    public function __construct(
        public readonly Algorithm $algorithm,
        public readonly string $challenge,
        public readonly int $number,
        public readonly string $salt,
        public readonly string $signature,
    ) {
    }
}
