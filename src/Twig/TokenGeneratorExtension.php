<?php

namespace NS\TokenBundle\Twig;

use Lcobucci\JWT\Token;
use NS\TokenBundle\Generator\LongTokenException;
use NS\TokenBundle\Generator\TokenGenerator;
use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;

class TokenGeneratorExtension extends AbstractExtension
{
    private TokenGenerator $generator;
    private int $short;
    private int $long;

    public function __construct(TokenGenerator $generator, int $short = 3600, int $long = 2592000)
    {
        $this->generator = $generator;
        $this->short     = $short;
        $this->long      = $long;
    }

    public function getFunctions(): array
    {
        return [
            new TwigFunction('generate_token', [$this, 'generateToken'], ['is_safe' => ['html']]),
            new TwigFunction('generate_short_token', [$this, 'generateShortToken'], ['is_safe' => ['html']]),
            new TwigFunction('generate_long_token', [$this, 'generateLongToken'], ['is_safe' => ['html']]),
        ];
    }

    public function generateShortToken(int $id, string $email, array $extraData = null): Token
    {
        return $this->generateToken($id, $email, $this->short, $extraData);
    }

    public function generateLongToken(int $id, string $email, array $extraData = null): Token
    {
        return $this->generateToken($id, $email, $this->long, $extraData);
    }

    public function generateToken(int $id, string $email, int $expiration, array $extraData = null): Token
    {
        $token    = $this->generator->getToken($id, $email, $extraData, $expiration);
        $tokenStr = $token->toString();
        if (strlen($tokenStr) > 2000) {
            throw new LongTokenException();
        }

        return $token;
    }
}
