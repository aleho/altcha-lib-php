<?php

use AltchaOrg\Altcha\Altcha;
use AltchaOrg\Altcha\BaseChallengeOptions;
use AltchaOrg\Altcha\Challenge;
use AltchaOrg\Altcha\ChallengeOptions;
use AltchaOrg\Altcha\Hasher\Algorithm;
use AltchaOrg\Altcha\Solution;
use PHPUnit\Framework\TestCase;

class AltchaTest extends TestCase
{
    private static Altcha $altcha;
    private static Challenge $challenge;

    public static function setUpBeforeClass(): void
    {
        // build a default challenge for all tests (for performance reasons)
        self::$altcha = new Altcha('test-key');
        self::$challenge = self::$altcha->createChallenge();
    }

    public function testCreateChallenge(): void
    {
        self::assertEquals(Algorithm::SHA256->value, self::$challenge->algorithm);
        self::assertNotEmpty(self::$challenge->challenge);
        self::assertEquals(BaseChallengeOptions::DEFAULT_MAX_NUMBER, self::$challenge->maxnumber);
        self::assertNotEmpty(self::$challenge->salt);
        self::assertNotEmpty(self::$challenge->signature);
    }

    public function testVerifyFieldsHash(): void
    {
        $formData = [
            'field1' => 'value1',
            'field2' => 'value2'
        ];

        $fields = ['field1', 'field2'];
        $fieldsHash = '1e823fb92790112edaa34e8cfed2afbb86054153932d8c2796d2c62727d287a6';

        $isValid = self::$altcha->verifyFieldsHash($formData, $fields, $fieldsHash, Algorithm::SHA256);

        self::assertTrue($isValid);
    }

    public function testSolveChallenge(): void
    {
        $solution = self::$altcha->solveChallenge(
            self::$challenge->challenge,
            self::$challenge->salt,
            Algorithm::from(self::$challenge->algorithm),
            self::$challenge->maxnumber
        );

        self::assertInstanceOf(Solution::class, $solution);
        self::assertEquals($solution->number, $solution->number);
        self::assertGreaterThan(0, $solution->took);
    }

    public function testVerifySolution(): void
    {
        $solution = self::$altcha->solveChallenge(
            self::$challenge->challenge,
            self::$challenge->salt,
            Algorithm::from(self::$challenge->algorithm),
            self::$challenge->maxnumber
        );

        self::assertInstanceOf(Solution::class, $solution);

        $payload = [
            'algorithm' => self::$challenge->algorithm,
            'challenge' => self::$challenge->challenge,
            'salt' => self::$challenge->salt,
            'signature' => self::$challenge->signature,
            'number' => $solution->number,
        ];

        $isValid = self::$altcha->verifySolution($payload);

        self::assertTrue($isValid);
    }

    public function testVerifyCustomOptions(): void
    {
        $altcha = new Altcha('my-key');
        $challenge = $altcha->createChallenge(new ChallengeOptions(
            algorithm: Algorithm::SHA1,
            maxNumber: 100,
            expires: (new \DateTimeImmutable())->add(new \DateInterval('PT10S')),
            params: ['custom_param' => '123'],
            saltLength: 3,
        ));

        $solution = $altcha->solveChallenge(
            $challenge->challenge,
            $challenge->salt,
            Algorithm::SHA1,
            100,
        );

        self::assertInstanceOf(Solution::class, $solution);

        $isValid = $altcha->verifySolution([
            'algorithm' => Algorithm::SHA1->value,
            'challenge' => $challenge->challenge,
            'salt' => $challenge->salt,
            'signature' => $challenge->signature,
            'number' => $solution->number,
        ]);

        self::assertTrue($isValid);
    }

    public function testInvalidPayload(): void
    {
        $isValid = self::$altcha->verifySolution('I am invalid');
        self::assertFalse($isValid);

        $verification = self::$altcha->verifyServerSignature('I am invalid');
        self::assertFalse($verification->verified);
    }
}
