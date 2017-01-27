<?php
/**
 * Created by PhpStorm.
 * User: gnat
 * Date: 06/06/16
 * Time: 11:01 AM.
 */
namespace NS\TokenBundle\Twig;

use NS\TokenBundle\Generator\LongTokenException;
use NS\TokenBundle\Generator\TokenGenerator;

class TokenGeneratorExtension extends \Twig_Extension
{
    /** @var TokenGenerator */
    private $generator;

    /**
     * TwigTokenGeneratorExtension constructor.
     *
     * @param TokenGenerator $generator
     */
    public function __construct(TokenGenerator $generator)
    {
        $this->generator = $generator;
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
        $this->generator->setExpiration(3600);
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
        $this->generator->setExpiration(2592000);
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
