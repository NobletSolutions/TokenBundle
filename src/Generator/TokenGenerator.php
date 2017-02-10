<?php
/**
 * Created by PhpStorm.
 * User: gnat
 * Date: 27/01/17
 * Time: 3:45 PM
 */

namespace NS\TokenBundle\Generator;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\ValidationData;

class TokenGenerator
{
    /** @var string */
    private $issuer;

    /** @var string */
    private $audience;

    /** @var int|null */
    private $expiration = 172800;

    /** @var string */
    private $id;

    /** @var string */
    private $key;

    /** @var Signer */
    private $signer;

    /**
     * TokenGenerator constructor.
     *
     * @param string $id
     * @param string $key
     * @param string $issuer
     * @param string|null $audience
     * @param string|null $expiration
     */
    public function __construct($id, $key, $issuer, $audience = null, $expiration = null)
    {
        $this->id = $id;
        $this->key = $key;
        $this->issuer = $issuer;
        $this->audience = ($audience !== null) ? $audience : $this->issuer;

        if ($expiration) {
            $this->expiration = $expiration;
        }
    }

    /**
     * @param $expiration
     */
    public function setExpiration($expiration)
    {
        $this->expiration = $expiration;
    }

    /**
     * @param string $signer
     */
    public function setSigner($signer)
    {
        if (!class_exists($signer)) {
            throw new \InvalidArgumentException(sprintf('Signer class %s does not exist', $signer));
        }

        $signerObj = new $signer();

        if (!$signerObj instanceof Signer) {
            throw new \InvalidArgumentException(sprintf('Signer class %s does not implement Lcobucci\JWT\Signer Interface', $signer));
        }

        $this->signer = $signerObj;
    }

    /**
     * @param $uId
     * @param $email
     * @param array|null $extraData
     *
     * @return \Lcobucci\JWT\Token
     */
    public function getToken($uId, $email, array $extraData = null)
    {
        $builder = new Builder();
        $builder->setIssuer($this->issuer)
            ->setAudience($this->audience)
            ->setId($this->id)
            ->setNotBefore(time())
            ->setExpiration(time() + $this->expiration)
            ->set('userId', $uId)
            ->set('email', $email);

        if ($extraData) {
            $builder->set('extra', serialize($extraData));
        }

        return ($this->signer) ? $builder->sign($this->signer, $this->key)->getToken() : $builder->getToken();
    }

    /**
     * @param $tokenStr
     *
     * @return array
     *
     * @throws InvalidTokenException
     */
    public function decryptToken($tokenStr)
    {
        $token = $this->parseToken($tokenStr);
        $extra = $token->hasClaim('extra') ? unserialize($token->getClaim('extra')) : null;

        return array($token->getClaim('userId'), $token->getClaim('email'), $extra);
    }

    /**
     * @param string $tokenStr
     *
     * @return bool
     */
    public function isValid($tokenStr)
    {
        try {
            $this->parseToken($tokenStr);

            return true;
        } catch (InvalidTokenException $exception) {
            return false;
        }
    }

    /**
     * @param string $tokenStr
     *
     * @return \Lcobucci\JWT\Token
     *
     * @throws InvalidTokenException
     */
    private function parseToken($tokenStr)
    {
        $token = (new Parser())->parse($tokenStr);

        if ($this->signer && !$token->verify($this->signer, $this->key)) {
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
