<?php declare(strict_types=1);

namespace NS\TokenBundle\Generator;

class LongTokenException extends \RuntimeException
{
    public function __construct()
    {
        parent::__construct("Token is too long for URL");
    }
}
