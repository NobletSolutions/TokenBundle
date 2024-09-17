<?php declare(strict_types=1);

namespace NS\TokenBundle\Generator;

class ParsedTokenResult
{
    private string $id;
    private string $email;
    private ?array $extra = null;

    public function __construct(string $id, string $email, ?array $extra = null)
    {
        $this->id    = $id;
        $this->email = $email;
        $this->extra = $extra;
    }

    public function getId(): string
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

    public function getExtra(string|int|null $field = null): null|string|int|array
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
