<?php

namespace NS\TokenBundle\Tests\Generator;

use NS\TokenBundle\Generator\ParsedTokenResult;
use PHPUnit\Framework\TestCase;

class ParsedTokenResultTest extends TestCase
{
    public function testGetAllExtra()
    {
        $extra = ['something'=>'nothing'];
        $parsed = new ParsedTokenResult(1,'user@example.net',$extra);
        $this->assertEquals($extra, $parsed->getExtra());
    }

    public function testGetExtraField()
    {
        $extra = ['something'=>'nothing'];
        $parsed = new ParsedTokenResult(1,'user@example.net',$extra);
        $this->assertEquals('nothing', $parsed->getExtra('something'));
    }

    public function testGetNonExistentExtraField()
    {
        $this->expectException('\InvalidArgumentException');
        $extra = ['something'=>'nothing'];
        $parsed = new ParsedTokenResult(1,'user@example.net',$extra);
        $this->assertEquals($extra, $parsed->getExtra('another'));
    }
}
