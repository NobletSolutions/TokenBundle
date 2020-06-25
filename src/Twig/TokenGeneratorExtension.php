<?php

namespace NS\TokenBundle\Twig;

use Lcobucci\JWT\Token;
use NS\TokenBundle\Generator\LongTokenException;
use NS\TokenBundle\Generator\TokenGenerator;
use Twig\Extension\AbstractExtension;
use Twig\TwigFunction;

class TokenGeneratorExtension extends AbstractExtension
{
    /** @var TokenGenerator */
    private $generator;

    /** @var int */
    private $short;

    /** @var int */
    private $long;

    /**
     * @param TokenGenerator $generator
     * @param int $short
     * @param int $long
     */
    public function __construct(TokenGenerator $generator, $short = 3600, $long = 2592000)
    {
        $this->generator = $generator;
        $this->short = $short;
        $this->long = $long;
    }

    /**
     * @return array
     */
    public function getFunctions()
    {
        return [
            new TwigFunction('generate_token', [$this, 'generateToken'], ['is_safe' => ['html']]),
            new TwigFunction('generate_short_token', [$this, 'generateShortToken'], ['is_safe' => ['html']]),
            new TwigFunction('generate_long_token', [$this, 'generateLongToken'], ['is_safe' => ['html']]),
        ];
    }

    /**
     * @param $id
     * @param $email
     * @param array|null $extraData
     *
     * @return Token
     */
    public function generateShortToken($id, $email, array $extraData = null)
    {
        $this->generator->setExpiration($this->short);
        return $this->generateToken($id, $email, $extraData);
    }

    /**
     * @param $id
     * @param $email
     * @param array|null $extraData
     *
     * @return Token
     */
    public function generateLongToken($id, $email, array $extraData = null)
    {
        $this->generator->setExpiration($this->long);
        return $this->generateToken($id, $email, $extraData);
    }

    /**
     * @param $id
     * @param $email
     * @param array|null $extraData
     *
     * @return Token
     */
    public function generateToken($id, $email, array $extraData = null)
    {
        $token = $this->generator->getToken($id, $email, $extraData);
        if (strlen($token) > 2000) {
            throw new LongTokenException();
        }

        return $token;
    }

    /**
     * @return string
     */
    public function getName()
    {
        return 'ns_token.twig_extension';
    }
}
