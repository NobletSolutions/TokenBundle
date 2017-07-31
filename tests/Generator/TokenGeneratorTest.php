<?php

namespace NS\TokenBundle\Tests\Generator;

use Lcobucci\JWT\Signer\Hmac\Sha256;
use NS\TokenBundle\Generator\TokenGenerator;

class TokenGeneratorTest extends \PHPUnit_Framework_TestCase
{
    public function testConstructor()
    {
        $generator = new TokenGenerator('id', 'key', 'issuer');
        $this->assertInstanceOf(TokenGenerator::class, $generator);
    }

    public function testTokenExpirationTime()
    {
        $generator = new TokenGenerator('id', 'key', 'issuer');
        $generator->setExpiration(3600);

        $time = time();
        $token = $generator->getToken(2, 'test@example.com');

        $this->assertEquals('issuer', $token->getClaim('iss'));
        $this->assertEquals('issuer', $token->getClaim('aud'));
        $this->assertEquals('none', $token->getHeader('alg'));
        $this->assertGreaterThanOrEqual($time + 3600, $token->getClaim('exp'));
        $this->assertGreaterThanOrEqual($time, $token->getClaim('nbf'));
        $parsed = $generator->decryptToken((string)$token);

        $this->assertEquals($parsed->getId(), 2);
        $this->assertEquals($parsed->getEmail(), 'test@example.com');
        $this->assertFalse($parsed->hasExtra());
        $this->assertNull($parsed->getExtra());
    }

    public function testTokenExtraData()
    {
        $generator = new TokenGenerator('id', 'key', 'issuer');

        $params = ['something' => 'another', 'whatever' => 4];
        $token = $generator->getToken(2, 'test@example.com', $params);

        $this->assertEquals('issuer', $token->getClaim('iss'));
        $this->assertEquals('issuer', $token->getClaim('aud'));
        $this->assertEquals('none', $token->getHeader('alg'));
        $parsed = $generator->decryptToken((string)$token);

        $this->assertEquals($parsed->getId(), 2);
        $this->assertEquals($parsed->getEmail(), 'test@example.com');
        $this->assertTrue($parsed->hasExtra());
        $this->assertEquals($params, $parsed->getExtra());
    }

    public function testTokenWithNoAudience()
    {
        $generator = new TokenGenerator('id', 'key', 'issuer');

        $time = time();
        $token = $generator->getToken(2, 'test@example.com');

        $this->assertEquals('issuer', $token->getClaim('iss'));
        $this->assertEquals('issuer', $token->getClaim('aud'));
        $this->assertEquals('none', $token->getHeader('alg'));
        $this->assertGreaterThanOrEqual($time + 172800, $token->getClaim('exp'));
        $this->assertGreaterThanOrEqual($time, $token->getClaim('nbf'));

        $parsed = $generator->decryptToken((string)$token);

        $this->assertEquals($parsed->getId(), 2);
        $this->assertEquals($parsed->getEmail(), 'test@example.com');
        $this->assertFalse($parsed->hasExtra());
        $this->assertNull($parsed->getExtra());
    }

    public function testTokenWithAudience()
    {
        $generator = new TokenGenerator('id', 'key', 'issuer', 'audience');

        $time = time();
        $token = $generator->getToken(2, 'test@example.com');

        $this->assertEquals('issuer', $token->getClaim('iss'));
        $this->assertEquals('audience', $token->getClaim('aud'));
        $this->assertEquals('none', $token->getHeader('alg'));
        $this->assertGreaterThanOrEqual($time + 172800, $token->getClaim('exp'));
        $this->assertGreaterThanOrEqual($time, $token->getClaim('nbf'));
        $parsed = $generator->decryptToken((string)$token);

        $this->assertEquals($parsed->getId(), 2);
        $this->assertEquals($parsed->getEmail(), 'test@example.com');
        $this->assertFalse($parsed->hasExtra());
        $this->assertNull($parsed->getExtra());
    }

    public function testTokenWithSigner()
    {
        $generator = new TokenGenerator('id', 'key', 'issuer', 'audience');
        $generator->setSigner(Sha256::class);

        $time = time();
        $token = $generator->getToken(2, 'test@example.com');

        $this->assertEquals('issuer', $token->getClaim('iss'));
        $this->assertEquals('audience', $token->getClaim('aud'));
        $this->assertGreaterThanOrEqual($time + 172800, $token->getClaim('exp'));
        $this->assertGreaterThanOrEqual($time, $token->getClaim('nbf'));

        $this->assertEquals('HS256', $token->getHeader('alg'));
        $parsed = $generator->decryptToken((string)$token);

        $this->assertEquals($parsed->getId(), 2);
        $this->assertEquals($parsed->getEmail(), 'test@example.com');
        $this->assertFalse($parsed->hasExtra());
        $this->assertNull($parsed->getExtra());
    }
}

