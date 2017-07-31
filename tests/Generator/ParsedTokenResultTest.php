<?php
/**
 * Created by PhpStorm.
 * User: gnat
 * Date: 31/07/17
 * Time: 12:27 PM
 */

namespace NS\TokenBundle\Tests\Generator;

use NS\TokenBundle\Generator\ParsedTokenResult;

class ParsedTokenResultTest extends \PHPUnit_Framework_TestCase
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
