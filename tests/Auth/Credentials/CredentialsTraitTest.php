<?php
/*
 * Copyright 2015 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace Google\Auth\Tests\Credentials;

use Google\Auth\Credentials\CredentialsTrait;
use PHPUnit\Framework\TestCase;
use Prophecy\Argument;

class CredentialsTraitTest extends TestCase
{
    private $mockCacheItem;
    private $mockCache;

    public function setUp(): void
    {
        $this->mockCacheItem = $this->prophesize('Psr\Cache\CacheItemInterface');
        $this->mockCache = $this->prophesize('Psr\Cache\CacheItemPoolInterface');
    }

    public function testSuccessfullyPullsFromCache()
    {
        $expectedValue = '1234';
        $this->mockCacheItem->isHit()
            ->shouldBeCalledTimes(1)
            ->willReturn(true);
        $this->mockCacheItem->get()
            ->shouldBeCalledTimes(1)
            ->willReturn($expectedValue);
        $this->mockCache->getItem(Argument::type('string'))
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockCacheItem->reveal());

        $implementation = new CredentialsTraitImplementation([
            'cache' => $this->mockCache->reveal(),
        ]);

        $cachedValue = $implementation->gCachedValue();
        $this->assertEquals($expectedValue, $cachedValue);
    }

    public function testSuccessfullyPullsFromCacheWithInvalidKey()
    {
        $key = 'this-key-has-@-illegal-characters';
        $expectedKey = 'thiskeyhasillegalcharacters';
        $expectedValue = '1234';
        $this->mockCacheItem->isHit()
            ->shouldBeCalledTimes(1)
            ->willReturn(true);
        $this->mockCacheItem->get()
            ->shouldBeCalledTimes(1)
            ->willReturn($expectedValue);
        $this->mockCache->getItem($expectedKey)
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockCacheItem->reveal());

        $implementation = new CredentialsTraitImplementation([
            'cache' => $this->mockCache->reveal(),
            'key' => $key,
        ]);

        $cachedValue = $implementation->gCachedValue();
        $this->assertEquals($expectedValue, $cachedValue);
    }

    public function testSuccessfullyPullsFromCacheWithLongKey()
    {
        $key = 'this-key-is-over-64-characters-and-it-will-still-work'
            . '-but-it-will-be-hashed-and-shortened';
        $expectedKey = str_replace('-', '', $key);
        $expectedKey = substr(hash('sha256', $expectedKey), 0, 64);
        $expectedValue = '1234';
        $this->mockCacheItem->isHit()
            ->shouldBeCalledTimes(1)
            ->willReturn(true);
        $this->mockCacheItem->get()
            ->shouldBeCalledTimes(1)
            ->willReturn($expectedValue);
        $this->mockCache->getItem($expectedKey)
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockCacheItem->reveal());

        $implementation = new CredentialsTraitImplementation([
            'cache' => $this->mockCache->reveal(),
            'key' => $key
        ]);

        $cachedValue = $implementation->gCachedValue();
        $this->assertEquals($expectedValue, $cachedValue);
    }

    public function testFailsPullFromCacheWithNoCache()
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Cache has not been initialized');
        $implementation = new CredentialsTraitImplementation([
            'cache' => null,
        ]);
        $cachedValue = $implementation->gCachedValue();
    }

    public function testSuccessfullySetsToCache()
    {
        $value = '1234';
        $this->mockCacheItem->set($value)
            ->shouldBeCalled();
        $this->mockCacheItem->expiresAfter(Argument::any())
            ->shouldBeCalled();
        $this->mockCache->getItem('key')
            ->willReturn($this->mockCacheItem->reveal());
        $this->mockCache->save(Argument::type('Psr\Cache\CacheItemInterface'))
            ->shouldBeCalled()
            ->willReturn(true);

        $implementation = new CredentialsTraitImplementation([
            'cache' => $this->mockCache->reveal(),
        ]);

        $implementation->sCachedValue($value);
    }

    public function testFailsSetToCacheWithNoCache()
    {
        $implementation = new CredentialsTraitImplementation();

        $implementation->sCachedValue('1234');

        $cachedValue = $implementation->sCachedValue('1234');
        $this->assertNull($cachedValue);
    }

    public function testFailsSetToCacheWithoutKey()
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Cache key cannot be empty');

        $this->mockCache->getItem(Argument::any())
            ->shouldNotBeCalled();

        $implementation = new CredentialsTraitImplementation([
            'cache' => $this->mockCache,
            'key'   => '',
        ]);

        $cachedValue = $implementation->sCachedValue('1234');
        $this->assertNull($cachedValue);
    }
}

class CredentialsTraitImplementation
{
    use CredentialsTrait;

    private $cache;
    private $cacheConfig;

    public function __construct(array $config = [])
    {
        $this->key = array_key_exists('key', $config) ? $config['key'] : 'key';
        $this->cache = isset($config['cache']) ? $config['cache'] : null;
        $this->cacheConfig = [
            'prefix' => '',
            'lifetime' => 1000,
        ];
    }

    // allows us to keep trait methods private
    public function gCachedValue()
    {
        return $this->getCachedValue($this->key);
    }

    public function sCachedValue($v)
    {
        $this->setCachedValue($this->key, $v);
    }
}
