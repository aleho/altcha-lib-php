<?php

declare(strict_types=1);

namespace AltchaOrg\Altcha;

/**
 * @phpstan-import-type ChallengeParams from BaseChallengeOptions
 */
class ChallengeOptions extends BaseChallengeOptions
{
    public const DEFAULT_ALGORITHM = Algorithm::SHA256;

    private const DEFAULT_SALT_LENGTH = 12;

    /**
     * Options for creation of a new challenge with sane defaults.
     *
     * @param string                  $hmacKey    Required HMAC key.
     * @param int                     $maxNumber  Maximum number for the random number generator (default: 1,000,000)
     * @param string                  $algorithm  Hashing algorithm to use (`SHA-1`, `SHA-256`, `SHA-512`, default:
     *                                            `SHA-256`).
     * @param \DateTimeInterface|null $expires    Optional expiration time for the challenge.
     * @param ChallengeParams         $params     Optional URL-encoded query parameters.
     * @param int<1, max>             $saltLength Length of the random salt (default: 12 bytes).
     */
    public function __construct(
        string $hmacKey,
        string $algorithm = self::DEFAULT_ALGORITHM,
        int $maxNumber = self::DEFAULT_MAX_NUMBER,
        ?\DateTimeInterface $expires = null,
        array $params = [],
        int $saltLength = self::DEFAULT_SALT_LENGTH
    ) {
        parent::__construct(
            $algorithm,
            $hmacKey,
            $maxNumber,
            $expires,
            bin2hex(self::randomBytes($saltLength)),
            self::randomInt($maxNumber),
            $params
        );
    }

    private static function randomInt(int $max): int
    {
        return random_int(0, $max);
    }

    /**
     * @param int<1, max> $length
     */
    private static function randomBytes(int $length): string
    {
        return random_bytes($length);
    }
}
