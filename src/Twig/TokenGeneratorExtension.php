<?php
namespace NS\TokenBundle\Twig;

use NS\TokenBundle\Generator\LongTokenException;
use NS\TokenBundle\Generator\TokenGenerator;

class TokenGeneratorExtension extends \Twig_Extension
{
    /** @var TokenGenerator */
    private $generator;

    /** @var int */
    private $short;

    /** @var int */
    private $long;

    /**
     * TwigTokenGeneratorExtension constructor.
     *
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
            new \Twig_SimpleFunction('generate_token', [$this, 'generateToken'], ['is_safe' => ['html']]),
            new \Twig_SimpleFunction('generate_short_token', [$this, 'generateShortToken'], ['is_safe' => ['html']]),
            new \Twig_SimpleFunction('generate_long_token', [$this, 'generateLongToken'], ['is_safe' => ['html']]),
        ];
    }

    /**
     * @param $id
     * @param $email
     * @param array|null $extraData
     *
     * @return \Lcobucci\JWT\Token
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
     * @return \Lcobucci\JWT\Token
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
     * @return \Lcobucci\JWT\Token
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
