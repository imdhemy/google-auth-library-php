<?php

namespace Google\Auth\Tests;

use GuzzleHttp\ClientInterface;
use PHPUnit\Framework\TestCase;

abstract class BaseTest extends TestCase
{
    /**
     * @see Google\Auth\$this->getValidKeyName
     */
    public function getValidKeyName($key)
    {
        return preg_replace('|[^a-zA-Z0-9_\.! ]|', '', $key);
    }
}
