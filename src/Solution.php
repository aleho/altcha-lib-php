<?php

declare(strict_types=1);

namespace AltchaOrg\Altcha;

class Solution
{
    public int $number;
    public float $took;

    public function __construct(int $number, float $took)
    {
        $this->number = $number;
        $this->took = $took;
    }
}
