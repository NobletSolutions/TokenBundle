<?php
/**
 * Created by PhpStorm.
 * User: gnat
 * Date: 01/08/16
 * Time: 3:21 PM
 */

namespace NS\TokenBundle\Generator;

class LongTokenException extends \RuntimeException
{
    /**
     * @inheritDoc
     */
    public function __construct()
    {
        parent::__construct("Token is too long for URL");
    }
}
