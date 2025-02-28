<?php

declare(strict_types=1);

namespace AltchaOrg\Altcha;

class ServerSignatureVerification
{
    public bool $verified;
    public ?ServerSignatureVerificationData $data;

    public function __construct(bool $verified, ?ServerSignatureVerificationData $data)
    {
        $this->verified = $verified;
        $this->data = $data;
    }
}
