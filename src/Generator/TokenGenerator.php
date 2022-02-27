<?php declare(strict_types=1);

namespace NS\TokenBundle\Generator;

use BadMethodCallException;
use DateTimeImmutable;
use Exception;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint\IdentifiedBy;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;

class TokenGenerator
{
    private Configuration $jwtConfig;
    private string $id;
    private string $issuer;
    private string $audience;
    private int $expiration = 172800;

    public function __construct(Configuration $jwtConfig, string $id, string $issuer, ?string $audience = null, ?int $expiration = null)
    {
        $this->jwtConfig = $jwtConfig;
        $this->id        = $id;
        $this->issuer    = $issuer;
        $this->audience  = $audience ?? $this->issuer;
        if ($expiration) {
            $this->expiration = $expiration;
        }
    }

    public function setExpiration(int $expiration): void
    {
        $this->expiration = $expiration;
    }

    public function getToken(string $uId, string $email, array $extraData = null, ?int $expiration = null, ?string $keyId = null): Token
    {
        $builder = $this->jwtConfig
            ->builder()
            ->issuedBy($this->issuer)
            ->permittedFor($this->audience)
            ->identifiedBy($this->id)
            ->canOnlyBeUsedAfter(new DateTimeImmutable())
            ->expiresAt(new DateTimeImmutable('@' . (time() + ($expiration > 0 ? $expiration : $this->expiration))))
            ->withClaim('userId', $uId)
            ->withClaim('email', $email);

        if ($extraData) {
            $builder->withClaim('extra', serialize($extraData));
        }

        if ($keyId) {
            $builder->withHeader('kid', $keyId);
        }

        return $builder->getToken($this->jwtConfig->signer(), $this->jwtConfig->signingKey());
    }

    /**
     * @throws InvalidTokenException
     */
    public function decryptToken($tokenStr): ParsedTokenResult
    {
        $token  = $this->parseToken($tokenStr);
        $claims = $token->claims();
        $extra  = $claims->has('extra') ? unserialize($claims->get('extra'), ['allowed_classes' => false]) : null;

        return new ParsedTokenResult($claims->get('userId'), $claims->get('email'), $extra);
    }

    public function isValid(string $tokenStr): bool
    {
        try {
            $this->parseToken($tokenStr);

            return true;
        } catch (InvalidTokenException $exception) {
            return false;
        }
    }

    /**
     * @throws InvalidTokenException
     */
    private function parseToken(string $tokenStr): Token
    {
        $constraints = [];
        try {
            $token = $this->jwtConfig->parser()->parse($tokenStr);
        } catch (Exception $exception) {
            throw new InvalidTokenException('Invalid token', 400, $exception);
        }

        $constraints[] = new IssuedBy($this->issuer);
        $constraints[] = new PermittedFor($this->audience);
        $constraints[] = new IdentifiedBy($this->id);
        $constraints[] = new SignedWith($this->jwtConfig->signer(), $this->jwtConfig->verificationKey());

        try {
            if (!$this->jwtConfig->validator()->validate($token, ...$constraints)) {
                throw new InvalidTokenException('Invalid token');
            }
        } catch (BadMethodCallException $exception) {
            throw new InvalidTokenException('Invalid token');
        }

        return $token;
    }
}
