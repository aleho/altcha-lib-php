<?php

declare(strict_types=1);

namespace AltchaOrg\Altcha;

use InvalidArgumentException;

/**
 * @phpstan-type PayloadData array{
 *     algorithm?: string,
 *     challenge?: string,
 *     number?: int,
 *     salt?: string,
 *     signature?: string,
 *     verificationData?: string,
 *     verified?: bool,
 * }
 */
class Altcha
{
    private static function hash(Algorithm $algorithm, string $data): string
    {
        return match ($algorithm) {
            Algorithm::SHA1   => sha1($data, true),
            Algorithm::SHA256 => hash('sha256', $data, true),
            Algorithm::SHA512 => hash('sha512', $data, true),
        };
    }

    public static function hashHex(Algorithm $algorithm, string $data): string
    {
        return bin2hex(self::hash($algorithm, $data));
    }

    private static function hmacHash(Algorithm $algorithm, string $data, string $key): string
    {
        return match ($algorithm) {
            Algorithm::SHA1   => hash_hmac('sha1', $data, $key, true),
            Algorithm::SHA256 => hash_hmac('sha256', $data, $key, true),
            Algorithm::SHA512 => hash_hmac('sha512', $data, $key, true),
        };
    }

    private static function hmacHex(Algorithm $algorithm, string $data, string $key): string
    {
        return bin2hex(self::hmacHash($algorithm, $data, $key));
    }

    /**
     * @param string $payload
     *
     * @return null|array<array-key, mixed>
     */
    private static function decodePayload(string $payload): ?array
    {
        $decoded = base64_decode($payload);

        if (!$decoded) {
            return null;
        }

        try {
            $data = json_decode($decoded, true, 2, JSON_THROW_ON_ERROR);
        } catch (\JsonException|\ValueError) {
            return null;
        }

        if (!is_array($data) || empty($data)) {
            return null;
        }

        return $data;
    }

    public static function createChallenge(BaseChallengeOptions $options): Challenge
    {
        $challenge = self::hashHex($options->algorithm, $options->salt . $options->number);
        $signature = self::hmacHex($options->algorithm, $challenge, $options->hmacKey);

        return new Challenge($options->algorithm->value, $challenge, $options->maxNumber, $options->salt, $signature);
    }

    /**
     * @param string|PayloadData $data
     */
    public static function verifySolution(string|array $data, string $hmacKey, bool $checkExpires = true): bool
    {
        if (is_string($data)) {
            /** @var PayloadData|null $data */
            $data = self::decodePayload($data);
        }

        if ($data === null
            || !isset($data['algorithm'], $data['challenge'], $data['number'], $data['salt'], $data['signature'])
        ) {
            return false;
        }

        $algorithm = Algorithm::tryFrom($data['algorithm']);

        if (!$algorithm) {
            throw new InvalidArgumentException("Unsupported algorithm: {$data['algorithm']}");
        }

        $payload = new Payload($algorithm, $data['challenge'], $data['number'], $data['salt'], $data['signature']);

        $params = self::extractParams($payload);
        if ($checkExpires && isset($params['expires']) && is_numeric($params['expires'])) {
            $expireTime = (int)$params['expires'];
            if (time() > $expireTime) {
                return false;
            }
        }

        $challengeOptions = new CheckChallengeOptions(
            $hmacKey,
            $payload->algorithm,
            $payload->salt,
            $payload->number
        );

        $expectedChallenge = self::createChallenge($challengeOptions);

        return $expectedChallenge->challenge === $payload->challenge &&
            $expectedChallenge->signature === $payload->signature;
    }

    /**
     * @return array<array-key, array<array-key, mixed>|string>
     */
    private static function extractParams(Payload $payload): array
    {
        $saltParts = explode('?', $payload->salt);
        if (count($saltParts) > 1) {
            parse_str($saltParts[1], $params);
            return $params;
        }
        return [];
    }

    /**
     * @param array<array-key, mixed> $formData
     * @param array<array-key, mixed> $fields
     */
    public static function verifyFieldsHash(array $formData, array $fields, string $fieldsHash, Algorithm $algorithm): bool
    {
        $lines = [];
        foreach ($fields as $field) {
            $lines[] = $formData[$field] ?? '';
        }
        $joinedData = implode("\n", $lines);
        $computedHash = self::hashHex($algorithm, $joinedData);
        return $computedHash === $fieldsHash;
    }

    /**
     * @param string|PayloadData $data
     */
    public static function verifyServerSignature(string|array $data, string $hmacKey): ServerSignatureVerification
    {
        if (is_string($data)) {
            /** @var PayloadData|null $data */
            $data = self::decodePayload($data);
        }

        if ($data === null
            || !isset($data['algorithm'], $data['verificationData'], $data['signature'], $data['verified'])
        ) {
            return new ServerSignatureVerification(false, null);
        }

        $algorithm = Algorithm::tryFrom($data['algorithm']);

        if (!$algorithm) {
            throw new InvalidArgumentException("Unsupported algorithm: {$data['algorithm']}");
        }

        $algorithm = Algorithm::tryFrom($data['algorithm']);

        if (!$algorithm) {
            throw new InvalidArgumentException("Unsupported algorithm: {$data['algorithm']}");
        }

        $payload = new ServerSignaturePayload($algorithm, $data['verificationData'], $data['signature'], $data['verified']);

        $hash = self::hash($payload->algorithm, $payload->verificationData);
        $expectedSignature = self::hmacHex($payload->algorithm, $hash, $hmacKey);

        parse_str($payload->verificationData, $params);

        $classification = isset($params['classification']) && is_string($params['classification']) ? $params['classification'] : '';
        $country = isset($params['country']) && is_string($params['country']) ? $params['country'] : '';
        $detectedLanguage = isset($params['detectedLanguage']) && is_string($params['detectedLanguage']) ? $params['detectedLanguage'] : '';
        $email = isset($params['email']) && is_string($params['email']) ? $params['email'] : '';
        $expire = isset($params['expire']) && is_numeric($params['expire']) ? (int) $params['expire'] : 0;
        $fields = isset($params['fields']) && is_array($params['fields']) ? $params['fields'] : [];
        $fieldsHash = isset($params['fieldsHash']) && is_string($params['fieldsHash']) ? $params['fieldsHash'] : '';
        $reasons = isset($params['reasons']) && is_array($params['reasons']) ? $params['reasons'] : [];
        $score = isset($params['score']) && is_numeric($params['score']) ? (float) $params['score'] : 0.0;
        $time = isset($params['time']) && is_numeric($params['time']) ? (int) $params['time'] : 0;
        $verified = isset($params['verified']) && $params['verified'];

        $verificationData = new ServerSignatureVerificationData(
            $classification,
            $country,
            $detectedLanguage,
            $email,
            $expire,
            $fields,
            $fieldsHash,
            $reasons,
            $score,
            $time,
            $verified,
        );

        $now = time();
        $isVerified = $payload->verified && $verificationData->verified &&
            $verificationData->expire > $now &&
            $payload->signature === $expectedSignature;

        return new ServerSignatureVerification($isVerified, $verificationData);
    }

    public static function solveChallenge(string $challenge, string $salt, Algorithm $algorithm, int $max, int $start = 0): ?Solution
    {
        $startTime = microtime(true);

        for ($n = $start; $n <= $max; $n++) {
            $hash = self::hashHex($algorithm, $salt . $n);
            if ($hash === $challenge) {
                $took = microtime(true) - $startTime;
                return new Solution($n, $took);
            }
        }

        return null;
    }
}
