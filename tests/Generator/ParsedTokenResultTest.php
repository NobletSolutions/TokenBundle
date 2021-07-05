<?php

namespace NS\TokenBundle\Tests\Generator;

use InvalidArgumentException;
use NS\TokenBundle\Generator\ParsedTokenResult;
use PHPUnit\Framework\TestCase;

class ParsedTokenResultTest extends TestCase
{
    public function testGetAllExtra(): void
    {
        $extra = ['something'=>'nothing'];
        $parsed = new ParsedTokenResult(1,'user@example.net',$extra);
        $this->assertEquals($extra, $parsed->getExtra());
    }

    public function testGetExtraField(): void
    {
        $extra = ['something'=>'nothing'];
        $parsed = new ParsedTokenResult(1,'user@example.net',$extra);
        $this->assertEquals('nothing', $parsed->getExtra('something'));
    }

    public function testGetNonExistentExtraField(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $extra = ['something'=>'nothing'];
        $parsed = new ParsedTokenResult(1,'user@example.net',$extra);
        $this->assertEquals($extra, $parsed->getExtra('another'));
    }
}
