<?php

namespace NS\TokenBundle\Generator;

use DateTimeImmutable;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;
use Lcobucci\JWT\Signer\Key;

class TokenGenerator
{
    private string $issuer;
    private string $audience;
    private int $expiration = 172800;
    private string $id;
    private Key $key;
    private ?Signer $signer = null;

    public function __construct(string $id, string $signer, $key, string $issuer, ?string $audience = null, ?int $expiration = null)
    {
        if (!class_exists($signer)) {
            throw new \InvalidArgumentException(sprintf('Signer class %s does not exist', $signer));
        }

        $signerObj = new $signer();

        if (!$signerObj instanceof Signer) {
            throw new \InvalidArgumentException(sprintf('Signer class %s does not implement Lcobucci\JWT\Signer Interface', $signer));
        }

        $this->signer   = $signerObj;
        $this->id       = $id;
        $this->key      = $key instanceof Key ? $key : new Key($key);
        $this->issuer   = $issuer;
        $this->audience = $audience ?? $this->issuer;

        if ($expiration) {
            $this->expiration = $expiration;
        }
    }

    public function setExpiration(int $expiration): void
    {
        $this->expiration = $expiration;
    }

    public function getToken(string $uId, string $email, array $extraData = null): Token
    {
        $builder = new Builder();
        $builder->issuedBy($this->issuer)
            ->permittedFor($this->audience)
            ->identifiedBy($this->id)
            ->canOnlyBeUsedAfter(new DateTimeImmutable())
            ->expiresAt(new DateTimeImmutable('@' . (time() + $this->expiration)))
            ->withClaim('userId', $uId)
            ->withClaim('email', $email);

        $builder->withClaim('iat', new DateTimeImmutable('@' . time()));

        if ($extraData) {
            $builder->withClaim('extra', serialize($extraData));
        }

        return $builder->getToken($this->signer, $this->key);
    }

    /**
     * @throws InvalidTokenException
     */
    public function decryptToken($tokenStr): ParsedTokenResult
    {
        $token = $this->parseToken($tokenStr);
        $extra = $token->hasClaim('extra') ? unserialize($token->getClaim('extra'), ['allowed_classes' => false]) : null;

        return new ParsedTokenResult($token->getClaim('userId'), $token->getClaim('email'), $extra);
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
        try {
            $token = (new Parser())->parse($tokenStr);
        } catch (\Exception $exception) {
            throw new InvalidTokenException('Invalid token', 400, $exception);
        }

        try {
            if ($this->signer && !$token->verify($this->signer, $this->key)) {
                throw new InvalidTokenException('Invalid token');
            }
        } catch (\BadMethodCallException $exception) {
            throw new InvalidTokenException('Invalid token');
        }

        $data = new ValidationData();
        $data->setId($this->id);
        $data->setIssuer($this->issuer);
        $data->setAudience($this->audience);

        if (!$token->validate($data)) {
            throw new InvalidTokenException('Invalid token');
        }

        return $token;
    }
}
