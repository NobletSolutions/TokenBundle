<?php

namespace NS\TokenBundle\Tests\Generator;

use NS\TokenBundle\Generator\TokenGenerator;

class TokenGeneratorTest extends \PHPUnit_Framework_TestCase
{
    public function testConstructor()
    {
	$generator = new TokenGenerator('id','key','issuer');
	$this->assertInstanceOf(TokenGenerator::class,$generator);
    }
}

