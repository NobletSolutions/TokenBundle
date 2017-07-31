<?php
/**
 * Created by PhpStorm.
 * User: gnat
 * Date: 31/07/17
 * Time: 12:14 PM
 */

namespace NS\TokenBundle\Generator;

class ParsedTokenResult
{
    /** @var string|integer */
    private $id;

    /** @var string */
    private $email;

    /** @var array */
    private $extra = null;

    /**
     * ParsedTokenResult constructor.
     * @param int|string $id
     * @param string $email
     * @param array $extra
     */
    public function __construct($id, $email, array $extra = null)
    {
        $this->id = $id;
        $this->email = $email;
        $this->extra = $extra;
    }

    /**
     * @return int|string
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * @return string
     */
    public function getEmail()
    {
        return $this->email;
    }

    /**
     * @return bool
     */
    public function hasExtra()
    {
        return $this->extra !== null;
    }

    /**
     * @return array
     */
    public function getExtra()
    {
        return $this->extra;
    }
}
