<?php

namespace NS\TokenBundle\Tests\Generator;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use NS\TokenBundle\Generator\InvalidTokenException;
use NS\TokenBundle\Generator\TokenGenerator;
use PHPUnit\Framework\TestCase;

class TokenGeneratorTest extends TestCase
{
    private Configuration $jwtConfig;

    public function setUp(): void
    {
        // the key requires min 256bits (8bits per char)
        $this->jwtConfig = Configuration::forSymmetricSigner(new Sha256(), InMemory::plainText('keykeykeykeykeykeykeykeykeykeyke'));
    }

    public function testConstructor(): void
    {
        $generator = new TokenGenerator($this->jwtConfig, 'id', 'issuer');
        $this->assertInstanceOf(TokenGenerator::class, $generator);
    }

    public function testTokenExpirationTime(): void
    {
        $generator = new TokenGenerator($this->jwtConfig, 'id', 'issuer', null, 3600);
        $time      = time();
        $token     = $generator->getToken('2', 'test@example.com');
        $claims    = $token->claims();
        $issuer    = $claims->get('iss');

        $this->assertEquals('issuer', $issuer);
        $this->assertEquals(['issuer'], $claims->get('aud'));
        $this->assertEquals('HS256', $token->headers()->get('alg'));
        $this->assertGreaterThanOrEqual($time + 3600, $claims->get('exp')->getTimestamp(), 'Expiration matches');
        $this->assertGreaterThanOrEqual($time, $claims->get('nbf')->getTimestamp());
        $parsed = $generator->decryptToken($token->toString());

        $this->assertEquals(2, $parsed->getId());
        $this->assertEquals('test@example.com', $parsed->getEmail());
        $this->assertFalse($parsed->hasExtra());
        $this->assertNull($parsed->getExtra());
    }

    public function testTokenOverrideExpirationTime(): void
    {
        $generator = new TokenGenerator($this->jwtConfig, 'id', 'issuer', null, 3600);
        $time      = time();
        $token     = $generator->getToken('2', 'test@example.com', null, 7200);
        $claims    = $token->claims();
        $issuer    = $claims->get('iss');

        $this->assertEquals('issuer', $issuer);
        $this->assertEquals(['issuer'], $claims->get('aud'));
        $this->assertEquals('HS256', $token->headers()->get('alg'));
        $this->assertGreaterThanOrEqual($time + 7200, $claims->get('exp')->getTimestamp(), 'Expiration matches');
        $this->assertGreaterThanOrEqual($time, $claims->get('nbf')->getTimestamp());
        $parsed = $generator->decryptToken($token->toString());

        $this->assertEquals(2, $parsed->getId());
        $this->assertEquals('test@example.com', $parsed->getEmail());
        $this->assertFalse($parsed->hasExtra());
        $this->assertNull($parsed->getExtra());
    }

    public function testTokenExtraData(): void
    {
        $generator = new TokenGenerator($this->jwtConfig, 'id', 'issuer');
        $params    = ['something' => 'another', 'whatever' => 4];
        $token     = $generator->getToken('2', 'test@example.com', $params);
        $claims    = $token->claims();
        $this->assertEquals('issuer', $claims->get('iss'));
        $this->assertEquals(['issuer'], $claims->get('aud'));
        $this->assertEquals('HS256', $token->headers()->get('alg'));
        $parsed = $generator->decryptToken($token->toString());

        $this->assertEquals(2, $parsed->getId());
        $this->assertEquals('test@example.com', $parsed->getEmail());
        $this->assertTrue($parsed->hasExtra());
        $this->assertEquals($params, $parsed->getExtra());
    }

    public function testTokenWithNoAudience(): void
    {
        $generator = new TokenGenerator($this->jwtConfig, 'id', 'issuer');
        $time      = time();
        $token     = $generator->getToken('2', 'test@example.com');
        $claims    = $token->claims();
        $this->assertEquals('issuer', $claims->get('iss'));
        $this->assertEquals(['issuer'], $claims->get('aud'));
        $this->assertEquals('HS256', $token->headers()->get('alg'));
        $this->assertGreaterThanOrEqual($time + 172800, $claims->get('exp')->getTimestamp());
        $this->assertGreaterThanOrEqual($time, $claims->get('nbf')->getTimestamp());

        $parsed = $generator->decryptToken($token->toString());

        $this->assertEquals(2, $parsed->getId());
        $this->assertEquals('test@example.com', $parsed->getEmail());
        $this->assertFalse($parsed->hasExtra());
        $this->assertNull($parsed->getExtra());
    }

    public function testTokenWithAudience(): void
    {
        $generator = new TokenGenerator($this->jwtConfig, 'id', 'issuer', 'audience');
        $time      = time();
        $token     = $generator->getToken('2', 'test@example.com');
        $claims    = $token->claims();
        $this->assertEquals('issuer', $claims->get('iss'));
        $this->assertEquals(['audience'], $claims->get('aud'));
        $this->assertEquals('HS256', $token->headers()->get('alg'));
        $this->assertGreaterThanOrEqual($time + 172800, $claims->get('exp')->getTimestamp());
        $this->assertGreaterThanOrEqual($time, $claims->get('nbf')->getTimestamp());
        $parsed = $generator->decryptToken($token->toString());

        $this->assertEquals(2, $parsed->getId());
        $this->assertEquals('test@example.com', $parsed->getEmail());
        $this->assertFalse($parsed->hasExtra());
        $this->assertNull($parsed->getExtra());
    }

    public function testTokenWithSigner(): void
    {
        $generator = new TokenGenerator($this->jwtConfig, 'id', 'issuer', 'audience');
        $time      = time();
        $token     = $generator->getToken('2', 'test@example.com');
        $claims    = $token->claims();

        $this->assertEquals('issuer', $claims->get('iss'));
        $this->assertEquals(['audience'], $claims->get('aud'));
        $this->assertGreaterThanOrEqual($time + 172800, $claims->get('exp')->getTimestamp());
        $this->assertGreaterThanOrEqual($time, $claims->get('nbf')->getTimestamp());

        $this->assertEquals('HS256', $token->headers()->get('alg'));
        $parsed = $generator->decryptToken($token->toString());

        $this->assertEquals(2, $parsed->getId());
        $this->assertEquals('test@example.com', $parsed->getEmail());
        $this->assertFalse($parsed->hasExtra());
        $this->assertNull($parsed->getExtra());
    }

    public function testNotAllowedSerializedObjects(): void
    {
        $generator      = new TokenGenerator($this->jwtConfig, 'id', 'issuer', 'audience');
        $time           = time();
        $stdClass       = new \stdClass();
        $stdClass->prop = 'something';
        $token          = $generator->getToken('2', 'test@example.com', ['hash' => 'blah blah blah', 'stdClass' => $stdClass]);
        $decrypted      = $generator->decryptToken($token->toString());
        $extra          = $decrypted->getExtra();
        self::assertArrayHasKey('stdClass', $extra);
        self::assertNotInstanceOf(\stdClass::class, $extra['stdClass']);
    }

    /**
     * @param $token
     *
     * @dataProvider getInvalidTokens
     */
    public function testInvalidToken($token): void
    {
        $this->expectException(InvalidTokenException::class);

        $generator = new TokenGenerator($this->jwtConfig, 'id', 'issuer', 'audience');

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

