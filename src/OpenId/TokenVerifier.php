<?php declare(strict_types=1);

namespace NS\TokenBundle\OpenId;

use CoderCat\JWKToPEM\JWKConverter;
use DateTimeZone;
use Exception;
use InvalidArgumentException;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use NS\TokenBundle\Generator\InvalidTokenException;
use Psr\Log\LoggerInterface;
use RuntimeException;
use Symfony\Contracts\HttpClient\HttpClientInterface;

class TokenVerifier
{
    private HttpClientInterface $httpClient;
    private Parser $parser;
    private Validator $validator;
    private JWKConverter $tokenConverter;
    private LoggerInterface $logger;

    public function __construct(HttpClientInterface $httpClient, Parser $parser, Validator $validator, JWKConverter $tokenConverter, LoggerInterface $logger)
    {
        $this->httpClient     = $httpClient;
        $this->parser         = $parser;
        $this->validator      = $validator;
        $this->tokenConverter = $tokenConverter;
        $this->logger         = $logger;
    }

    public function isValid(string $tokenStr, string $allowableIssuer): bool
    {
        $this->logger->debug('TokenVerifier: ' . __METHOD__ . ': ' . __LINE__);

        if (!filter_var($allowableIssuer, FILTER_VALIDATE_URL)) {
            $this->logger->debug('TokenVerifier: We can only validate url based issuers ' . $allowableIssuer);
            throw new InvalidArgumentException('We can only validate url based issuers');
        }

        try {
            $token       = $this->parser->parse($tokenStr);
            $constraints = [new IssuedBy($allowableIssuer), new LooseValidAt(new SystemClock(new DateTimeZone('America/Edmonton')))];

            $openIdConfigUrl = sprintf('%s/.well-known/openid-configuration', $allowableIssuer);
            $config          = $this->get($openIdConfigUrl);
            if (!$config) {
                $this->logger->debug('TokenVerifier: No OpenId Config found ' . $openIdConfigUrl);
                throw new RuntimeException('No OpenId Config found');
            }

            $configArray = json_decode($config, true, 256, JSON_THROW_ON_ERROR);
            if (!isset($configArray['jwks_uri'])) {
                $this->logger->debug('TokenVerifier: No Valid JWKS_URI found');
                throw new RuntimeException('No valid jwks_uri');
            }

            $jwks = $this->get($configArray['jwks_uri']);
            if (!$jwks) {
                $this->logger->debug('TokenVerifier: No JWKS Config found');
                throw new RuntimeException('No JWKs config found');
            }

            $jwksConfig = json_decode($jwks, true, 256, JSON_THROW_ON_ERROR);
            if (!isset($jwksConfig['keys'])) {
                $this->logger->debug('TokenVerifier: Invalid JWK json');
                throw new RuntimeException('Invalid JWK json');
            }

            $found = false;
            $keyId = $token->headers()->get('kid');
            foreach ($jwksConfig['keys'] as $key) {
                if (isset($key['kid']) && $keyId === $key['kid']) {
                    $signer = SignerLocator::getSigner($key['alg']);
                    if (!$signer) {
                        $this->logger->debug('TokenVerifier: Unable to locate appropriate signer');
                        throw new RuntimeException('Unable to locate appropriate signer');
                    }
                    $PEM           = $this->tokenConverter->toPEM($key);
                    $constraints[] = new SignedWith($signer, InMemory::plainText($PEM));
                    $found         = true;
                    break;
                }
            }

            if (!$found) {
                $this->logger->debug('TokenVerifier: Unable to locate key for token');
                throw new RuntimeException('Unable to locate key for token');
            }

            foreach ($constraints as $constraint) {
                $ret = $this->validator->validate($token, $constraint);
                if (!$ret) {
                    $this->logger->debug('TokenVerifier: Invalid Token - Validation failed');
                    return false;
                }
            }

            return true;
        } catch (Exception|\Throwable $exception) {
            $this->logger->debug('TokenVerifier: Invalid Token: ' . $exception->getMessage());
            throw new InvalidTokenException('Invalid token', 107, $exception);
        }
    }

    private function get(string $url): ?string
    {
        try {
            return $this->httpClient->request('GET', $url)->getContent();
        } catch (Exception $exception) {
            return null;
        }
    }
}
