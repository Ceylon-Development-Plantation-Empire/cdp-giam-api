<?php

namespace App\Exceptions;

use Exception;

class IntegrationActivationException extends Exception
{
    /**
     * List of missing configuration or credential fields preventing activation.
     *
     * @var array<int, string>
     */
    protected array $missingFields;

    public function __construct(string $message = '', array $missingFields = [], int $code = 422, ?Exception $previous = null)
    {
        parent::__construct($message, $code, $previous);
        $this->missingFields = $missingFields;
    }

    /**
     * Get missing field names.
     *
     * @return array<int, string>
     */
    public function getMissingFields(): array
    {
        return $this->missingFields;
    }
}
