<?php
/*
 * Copyright 2020 Google LLC
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

declare(strict_types=1);

namespace Google\Auth\Credentials;

use Google\Cache\MemoryCacheItemPool;
use Google\Http\ClientInterface;
use Psr\Cache\CacheItemPoolInterface;

/**
 * Trait for shared functionality between credentials classes.
 *
 * @internal
 */
trait CredentialsTrait
{
    private $maxCacheKeyLength = 64;

    /**
     * @var ClientInterface
     */
    private $httpClient;

    /**
     * @var CacheItemPoolInterface
     */
    private $cache;

    /**
     * @var int
     */
    private $cacheLifetime = 1500;

    /**
     * @var string
     */
    private $cachePrefix = '';

    /**
     * Returns request headers containing the authorization token
     *
     * @return array
     */
    public function getRequestMetadata(): array
    {
        $result = $this->fetchAuthToken($httpHandler);
        if (isset($result['access_token'])) {
            return ['Authorization' => 'Bearer ' . $result['access_token']];
        }

        return [];
    }

    /**
     *
     */
    private function setHttpClientFromOptions(array $options): void
    {
        if (empty($options['httpClient'])) {
            throw new \RuntimeException('Missing required option "httpClient"');
        }
        if (!$options['httpClient'] instanceof ClientInterface) {
            throw new \RuntimeException(sprintf(
                'Invalid option "httpClient": must be an instance of %s',
                ClientInterface::class
            ));
        }
        $this->httpClient = $options['httpClient'];
    }

    /**
     *
     */
    private function setCacheFromOptions(array $options): void
    {
        if (!empty($options['cache'])) {
            if (!$options['cache'] instanceof CacheItemPoolInterface) {
                throw new \RuntimeException(sprintf(
                    'Invalid option "cache": must be an instance of %s',
                    CacheItemPoolInterface::class
                ));
            }
            $this->cache = $options['cache'];
        } else {
            $this->cache = new MemoryCacheItemPool();
        }
        if (array_key_exists('cacheLifetime', $options)) {
            $this->cacheLifetime = (int) $options['cacheLifetime'];
        }
        if (array_key_exists('cachePrefix', $options)) {
            $this->cachePrefix = (string) $options['cachePrefix'];
        }
    }

    /**
     * Gets the cached value if it is present in the cache when that is
     * available.
     */
    private function getCachedValue(string $k)
    {
        if (is_null($this->cache)) {
            throw new \LogicException('Cache has not been initialized');
        }

        $key = $this->getFullCacheKey($k);

        $cacheItem = $this->cache->getItem($key);
        if ($cacheItem->isHit()) {
            return $cacheItem->get();
        }
    }

    /**
     * Saves the value in the cache when that is available.
     */
    private function setCachedValue(string $k, $v): bool
    {
        if (is_null($this->cache)) {
            return false;
        }

        $key = $this->getFullCacheKey($k);

        $cacheItem = $this->cache->getItem($key);
        $cacheItem->set($v);
        $cacheItem->expiresAfter($this->cacheLifetime);
        return $this->cache->save($cacheItem);
    }

    private function getFullCacheKey(string $key): string
    {
        if (empty($key)) {
            throw new \LogicException('Cache key cannot be empty');
        }

        $key = $this->cachePrefix . $key;

        // ensure we do not have illegal characters
        $key = preg_replace('|[^a-zA-Z0-9_\.!]|', '', $key);

        // Hash keys if they exceed $maxKeyLength (defaults to 64)
        if (strlen($key) > $this->maxCacheKeyLength) {
            $key = substr(hash('sha256', $key), 0, $this->maxCacheKeyLength);
        }

        return $key;
    }
}
