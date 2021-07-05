<?php

namespace NS\TokenBundle\Generator;

class ParsedTokenResult
{
    private int $id;

    private string $email;

    private ?array $extra;

    public function __construct(int $id, string $email, array $extra = null)
    {
        $this->id = $id;
        $this->email = $email;
        $this->extra = $extra;
    }

    public function getId(): int
    {
        return $this->id;
    }

    public function getEmail(): string
    {
        return $this->email;
    }

    public function hasExtra(): bool
    {
        return $this->extra !== null;
    }

    /**
     * @param string|int|null $field
     * @return mixed string|int|array
     */
    public function getExtra($field = null)
    {
        if ($field !== null) {
            if (isset($this->extra[$field])) {
                return $this->extra[$field];
            }

            throw new \InvalidArgumentException("Extra Field '$field' doesn't exist");
        }

        return $this->extra;
    }
}
