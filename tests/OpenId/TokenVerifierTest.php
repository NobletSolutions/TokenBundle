<?php declare(strict_types=1);

namespace NS\TokenBundle\Tests\OpenId;

use CoderCat\JWKToPEM\JWKConverter;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Validation\Validator;
use NS\TokenBundle\Generator\InvalidTokenException;
use NS\TokenBundle\OpenId\TokenVerifier;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\Exception\TransportException;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;

class TokenVerifierTest extends TestCase
{
    private Parser $parser;
    private JWKConverter $tokenConverter;
    private Validator $validator;
    /** @var HttpClientInterface|MockObject */
    private $httpClient;

    private ?TokenVerifier $tokenVerifier = null;

    public function setUp(): void
    {
        $this->parser         = new Parser();
        $this->tokenConverter = new JWKConverter();
        $this->validator      = new Validator();
        $this->httpClient     = $this->createMock(HttpClientInterface::class);
        $this->tokenVerifier = new TokenVerifier($this->httpClient, $this->parser, $this->validator, $this->tokenConverter);
    }

    public function testNonUrlIssuerThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->tokenVerifier->isValid('a string','non_url');
    }

    public function testUnableToLocateOpenIdConfigurationThrowsException(): void
    {
        $this->expectException(InvalidTokenException::class);

        $response = $this->createMock(ResponseInterface::class);
        $response->method('getContent')->willThrowException(new TransportException());
        $this->httpClient->method('request')->with('GET', 'http://example.net/.well-known/openid-configuration')->willReturn($response);
        $this->tokenVerifier->isValid('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c','https://example.net');
    }

    public function testOpenIdInvalidResponse(): void
    {
        $this->expectException(InvalidTokenException::class);

        $response = $this->createMock(ResponseInterface::class);
        $response->method('getContent')->willReturn(file_get_contents(__DIR__.'/Fixtures/not-json.response'));
        $this->httpClient->method('request')->with('GET', 'http://example.net/.well-known/openid-configuration')->willReturn($response);
        $this->tokenVerifier->isValid('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c','https://example.net');
    }

    public function testOpenIdMissingJwksUri(): void
    {
        $this->expectException(InvalidTokenException::class);

        $response = $this->createMock(ResponseInterface::class);
        $response->method('getContent')->willReturn(file_get_contents(__DIR__.'/Fixtures/openid-missing-jwks_uri.response'));
        $this->httpClient->method('request')->with('GET', 'http://example.net/.well-known/openid-configuration')->willReturn($response);
        $this->tokenVerifier->isValid('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c','https://example.net');
    }

    public function testJwksEmpty(): void
    {
        $this->expectException(InvalidTokenException::class);

        $openIdResponse = $this->createMock(ResponseInterface::class);
        $jwksIdResponse = $this->createMock(ResponseInterface::class);
        $openIdResponse->method('getContent')->willReturn(file_get_contents(__DIR__.'/Fixtures/openid-config.response'));
        $jwksIdResponse->method('getContent')->willReturn(new TransportException());

        $this->httpClient->method('request')->willReturnCallback(static function($method, $url) use ($openIdResponse, $jwksIdResponse) {
            self::assertSame('GET', $method);
            if ($url === 'https://example.net/.well-known/openid-configuration') {
                return $openIdResponse;
            }

            if ($url === 'https://example.net/.well-known/jwks') {
                return $jwksIdResponse;
            }

            throw new \RuntimeException('No matching url for '.$url);
        });
        $this->tokenVerifier->isValid('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c','https://example.net');
    }
}
