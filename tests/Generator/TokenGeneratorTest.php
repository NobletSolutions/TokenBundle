<?php

namespace NS\TokenBundle\Tests\Generator;

use Lcobucci\JWT\Signer\Hmac\Sha256;
use NS\TokenBundle\Generator\InvalidTokenException;
use NS\TokenBundle\Generator\TokenGenerator;
use PHPUnit\Framework\TestCase;

class TokenGeneratorTest extends TestCase
{
    public function testConstructor(): void
    {
        $generator = new TokenGenerator('id', Sha256::class, 'key', 'issuer');
        $this->assertInstanceOf(TokenGenerator::class, $generator);
    }

    public function testTokenExpirationTime(): void
    {
        $generator = new TokenGenerator('id', Sha256::class, 'key', 'issuer');
        $generator->setExpiration(3600);

        $time = time();
        $token = $generator->getToken('2', 'test@example.com');

        $this->assertEquals('issuer', $token->getClaim('iss'));
        $this->assertEquals('issuer', $token->getClaim('aud'));
        $this->assertEquals('HS256', $token->getHeader('alg'));
        $this->assertGreaterThanOrEqual($time + 3600, $token->getClaim('exp'));
        $this->assertGreaterThanOrEqual($time, $token->getClaim('nbf'));
        $parsed = $generator->decryptToken((string)$token);

        $this->assertEquals(2, $parsed->getId());
        $this->assertEquals('test@example.com', $parsed->getEmail());
        $this->assertFalse($parsed->hasExtra());
        $this->assertNull($parsed->getExtra());
    }

    public function testTokenExtraData(): void
    {
        $generator = new TokenGenerator('id', Sha256::class, 'key', 'issuer');

        $params = ['something' => 'another', 'whatever' => 4];
        $token = $generator->getToken('2', 'test@example.com', $params);

        $this->assertEquals('issuer', $token->getClaim('iss'));
        $this->assertEquals('issuer', $token->getClaim('aud'));
        $this->assertEquals('HS256', $token->getHeader('alg'));
        $parsed = $generator->decryptToken((string)$token);

        $this->assertEquals(2, $parsed->getId());
        $this->assertEquals('test@example.com', $parsed->getEmail());
        $this->assertTrue($parsed->hasExtra());
        $this->assertEquals($params, $parsed->getExtra());
    }

    public function testTokenWithNoAudience(): void
    {
        $generator = new TokenGenerator('id', Sha256::class, 'key', 'issuer');

        $time = time();
        $token = $generator->getToken('2', 'test@example.com');

        $this->assertEquals('issuer', $token->getClaim('iss'));
        $this->assertEquals('issuer', $token->getClaim('aud'));
        $this->assertEquals('HS256', $token->getHeader('alg'));
        $this->assertGreaterThanOrEqual($time + 172800, $token->getClaim('exp'));
        $this->assertGreaterThanOrEqual($time, $token->getClaim('nbf'));

        $parsed = $generator->decryptToken((string)$token);

        $this->assertEquals(2, $parsed->getId());
        $this->assertEquals('test@example.com', $parsed->getEmail());
        $this->assertFalse($parsed->hasExtra());
        $this->assertNull($parsed->getExtra());
    }

    public function testTokenWithAudience(): void
    {
        $generator = new TokenGenerator('id', Sha256::class, 'key', 'issuer', 'audience');

        $time = time();
        $token = $generator->getToken('2', 'test@example.com');

        $this->assertEquals('issuer', $token->getClaim('iss'));
        $this->assertEquals('audience', $token->getClaim('aud'));
        $this->assertEquals('HS256', $token->getHeader('alg'));
        $this->assertGreaterThanOrEqual($time + 172800, $token->getClaim('exp'));
        $this->assertGreaterThanOrEqual($time, $token->getClaim('nbf'));
        $parsed = $generator->decryptToken((string)$token);

        $this->assertEquals(2, $parsed->getId());
        $this->assertEquals('test@example.com', $parsed->getEmail());
        $this->assertFalse($parsed->hasExtra());
        $this->assertNull($parsed->getExtra());
    }

    public function testTokenWithSigner(): void
    {
        $generator = new TokenGenerator('id', Sha256::class, 'key', 'issuer', 'audience');

        $time = time();
        $token = $generator->getToken('2', 'test@example.com');

        $this->assertEquals('issuer', $token->getClaim('iss'));
        $this->assertEquals('audience', $token->getClaim('aud'));
        $this->assertGreaterThanOrEqual($time + 172800, $token->getClaim('exp'));
        $this->assertGreaterThanOrEqual($time, $token->getClaim('nbf'));

        $this->assertEquals('HS256', $token->getHeader('alg'));
        $parsed = $generator->decryptToken((string)$token);

        $this->assertEquals(2, $parsed->getId());
        $this->assertEquals('test@example.com', $parsed->getEmail());
        $this->assertFalse($parsed->hasExtra());
        $this->assertNull($parsed->getExtra());
    }

    public function testNotAllowedSerializedObjects(): void
    {
        $generator = new TokenGenerator('id', Sha256::class, 'key', 'issuer', 'audience');

        $time = time();
        $stdClass = new \stdClass();
        $stdClass->prop = 'something';
        $token = $generator->getToken('2', 'test@example.com', ['hash' => 'blah blah blah', 'stdClass' => $stdClass]);
        $decrypted = $generator->decryptToken((string)$token);
        $extra = $decrypted->getExtra();
        self::assertArrayHasKey('stdClass', $extra);
        self::assertNotInstanceOf(\stdClass::class, $extra['stdClass']);
    }

    /**
     * @param $token
     * @dataProvider getInvalidTokens
     */
    public function testInvalidToken($token): void
    {
        $this->expectException(InvalidTokenException::class);

        $generator = new TokenGenerator('id', Sha256::class, 'key', 'issuer', 'audience');
        $generator->decryptToken($token);
    }

    public function getInvalidTokens(): array
    {
        return [
            ['something.totally.invalid'],
            ['no dots'],
        ];
    }
}

