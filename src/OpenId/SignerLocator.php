<?php declare(strict_types=1);

namespace NS\TokenBundle\OpenId;

use Lcobucci\JWT\Signer;

class SignerLocator
{
    public static function getSigner(string $algorithm): ?Signer
    {
        switch ($algorithm) {
            case 'RS256':
                return new Signer\Rsa\Sha256();
            case 'RS384':
                return new Signer\Rsa\Sha384();
            case 'RS512':
                return new Signer\Rsa\Sha512();
            case 'HS256':
                return new Signer\Hmac\Sha256();
            case 'HS384':
                return new Signer\Hmac\Sha384();
            case 'HS512':
                return new Signer\Hmac\Sha512();
            case 'ES256':
                return new Signer\Ecdsa\Sha256(new Signer\Ecdsa\MultibyteStringConverter());
            case 'ES384':
                return new Signer\Ecdsa\Sha384(new Signer\Ecdsa\MultibyteStringConverter());
            case 'ES512':
                return new Signer\Ecdsa\Sha512(new Signer\Ecdsa\MultibyteStringConverter());
        }

        return null;
    }
}
