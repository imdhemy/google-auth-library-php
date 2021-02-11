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

namespace Google\Auth\Tests;

use Google\Auth\GoogleAuth;
use Google\Auth\Credentials\ComputeCredentials;
use Google\Auth\Credentials\ServiceAccountCredentials;
use Google\Auth\Credentials\UserRefreshCredentials;
use Google\Auth\Jwt\JwtClientInterface;
use GuzzleHttp\Psr7;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;
use ReflectionClass;
use Prophecy\Argument;

/**
 * @runTestsInSeparateProcesses
 */
class GoogleAuthTest extends BaseTest
{
    private const TEST_TARGET_AUDIENCE = 'a target audience';
    private const TEST_QUOTA_PROJECT = 'a-quota-project';
    private const TEST_TOKEN = 'foobar';
    private const OIDC_CERTS_HASH = '383205148db079b1df1a9fa3785d5b56f47d7b30';

    private $mockCacheItem;
    private $mockCache;

    protected function setUp(): void
    {
        putenv('HOME');
        putenv('GOOGLE_APPLICATION_CREDENTIALS');
        $this->mockCacheItem = $this->prophesize(CacheItemInterface::class);
        $this->mockCache = $this->prophesize(CacheItemPoolInterface::class);
    }

    public function testCachedOnComputeTrueValue()
    {
        $cachedValue = true;
        $this->mockCacheItem->isHit()
            ->shouldBeCalledTimes(1)
            ->willReturn(true);
        $this->mockCacheItem->get()
            ->shouldBeCalledTimes(1)
            ->willReturn($cachedValue);
        $this->mockCache->getItem('google_auth_on_gce_cache')
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockCacheItem->reveal());

        // Run the test.
        $googleAuth = new GoogleAuth(['cache' => $this->mockCache->reveal()]);
        $this->assertTrue($googleAuth->onCompute());
    }

    public function testCachedOnComputeFalseValue()
    {
        $cachedValue = false;
        $this->mockCacheItem->isHit()
            ->shouldBeCalledTimes(1)
            ->willReturn(true);
        $this->mockCacheItem->get()
            ->shouldBeCalledTimes(1)
            ->willReturn($cachedValue);
        $this->mockCache->getItem('google_auth_on_gce_cache')
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockCacheItem->reveal());

        // Run the test.
        $googleAuth = new GoogleAuth(['cache' => $this->mockCache->reveal()]);
        $this->assertFalse($googleAuth->onCompute());
    }

    public function testUncachedOnCompute()
    {
        $gceIsCalled = false;
        $httpClient = httpClientFromCallable(function ($request) use (&$gceIsCalled) {
            $gceIsCalled = true;
            return new Response(200, ['Metadata-Flavor' => 'Google']);
        });

        $this->mockCacheItem->isHit()
            ->shouldBeCalledTimes(1)
            ->willReturn(false);
        $this->mockCacheItem->set(true)
            ->shouldBeCalledTimes(1);
        $this->mockCacheItem->expiresAfter(1500)
            ->shouldBeCalledTimes(1);
        $this->mockCache->getItem('google_auth_on_gce_cache')
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockCacheItem->reveal());
        $this->mockCache->save($this->mockCacheItem->reveal())
            ->shouldBeCalledTimes(1);

        // Run the test.
        $googleAuth = new GoogleAuth([
            'cache' => $this->mockCache->reveal(),
            'httpClient' => $httpClient,
        ]);

        $this->assertTrue($googleAuth->onCompute());
        $this->assertTrue($gceIsCalled);
    }

    public function testShouldFetchFromCacheWithCacheOptions()
    {
        $prefix = 'test_prefix_';
        $lifetime = '70707';
        $cachedValue = true;

        $this->mockCacheItem->isHit()
            ->willReturn(true);
        $this->mockCacheItem->get()
            ->willReturn($cachedValue);
        $this->mockCache->getItem($prefix . 'google_auth_on_gce_cache')
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockCacheItem->reveal());

        // Run the test
        $googleAuth = new GoogleAuth([
            'cachePrefix' => $prefix,
            'cacheLifetime' => $lifetime,
            'cache' => $this->mockCache->reveal(),
        ]);
        $this->assertTrue($googleAuth->onCompute());
    }

    public function testShouldSaveValueInCacheWithCacheOptions()
    {
        $prefix = 'test_prefix_';
        $lifetime = '70707';
        $gceIsCalled = false;
        $httpClient = httpClientFromCallable(function ($request) use (&$gceIsCalled) {
            $gceIsCalled = true;
            return new Response(200, ['Metadata-Flavor' => 'Google']);
        });
        $this->mockCacheItem->isHit()
            ->willReturn(false);
        $this->mockCacheItem->set(true)
            ->shouldBeCalledTimes(1);
        $this->mockCacheItem->expiresAfter($lifetime)
            ->shouldBeCalledTimes(1);
        $this->mockCache->getItem($prefix . 'google_auth_on_gce_cache')
            ->shouldBeCalledTimes(1)
            ->willReturn($this->mockCacheItem->reveal());
        $this->mockCache->save($this->mockCacheItem->reveal())
            ->shouldBeCalled();

        // Run the test
        $googleAuth = new GoogleAuth([
            'cachePrefix' => $prefix,
            'cacheLifetime' => $lifetime,
            'cache' => $this->mockCache->reveal(),
            'httpClient' => $httpClient,
        ]);
        $onCompute = $googleAuth->onCompute();
        $this->assertTrue($onCompute);
        $this->assertTrue($gceIsCalled);
    }

    public function testIsFailsEnvSpecifiesNonExistentFile()
    {
        $this->expectException('DomainException');

        $keyFile = __DIR__ . '/fixtures' . '/does-not-exist-private.json';
        putenv('GOOGLE_APPLICATION_CREDENTIALS=' . $keyFile);
        (new GoogleAuth())->makeCredentials(['scope' => 'a scope']);
    }

    public function testLoadsOKIfEnvSpecifiedIsValid()
    {
        $keyFile = __DIR__ . '/fixtures' . '/private.json';
        putenv('GOOGLE_APPLICATION_CREDENTIALS=' . $keyFile);
        $this->assertNotNull(
            (new GoogleAuth())->makeCredentials(['scope' => 'a scope'])
        );
    }

    public function testLoadsDefaultFileIfPresentAndEnvVarIsNotSet()
    {
        putenv('HOME=' . __DIR__ . '/fixtures');
        $this->assertNotNull(
            (new GoogleAuth())->makeCredentials(['scope' => 'a scope'])
        );
    }

    public function testFailsIfNotOnGceAndNoDefaultFileFound()
    {
        $this->expectException('DomainException');

        putenv('HOME=' . __DIR__ . '/not_exist_fixtures');
        // simulate not being GCE and retry attempts by returning multiple 500s
        $httpClient = httpClientWithResponses([
            new Response(500),
            new Response(500),
            new Response(500)
        ]);
        $googleAuth = new GoogleAuth([
            'httpClient' => $httpClient,
        ]);
        $googleAuth->makeCredentials(['scope' => 'a scope']);
    }

    public function testSuccedsIfNoDefaultFilesButIsOnCompute()
    {
        $wantedTokens = [
            'access_token' => '1/abdef1234567890',
            'expires_in' => '57',
            'token_type' => 'Bearer',
        ];
        $jsonTokens = json_encode($wantedTokens);

        // simulate the response from GCE.
        $httpClient = httpClientWithResponses([
            new Response(200, ['Metadata-Flavor' => 'Google']),
            new Response(200, [], Psr7\stream_for($jsonTokens)),
        ]);
        $googleAuth = new GoogleAuth([
            'httpClient' => $httpClient,
        ]);
        $this->assertNotNull(
            $googleAuth->makeCredentials(['scope' => 'a scope'])
        );
    }

    public function testComputeCredentials()
    {
        $jsonTokens = json_encode(['access_token' => 'abc']);
        $httpClient = httpClientWithResponses([
            new Response(200, ['Metadata-Flavor' => 'Google']),
            new Response(200, [], Psr7\stream_for($jsonTokens)),
        ]);
        $googleAuth = new GoogleAuth([
            'httpClient' => $httpClient,
        ]);
        $credentials = $googleAuth->makeCredentials([
            'defaultScope' => 'a-default-scope'
        ]);

        $this->assertInstanceOf(ComputeCredentials::class, $credentials);

        $uriProperty = (new ReflectionClass($credentials))->getProperty('tokenUri');
        $uriProperty->setAccessible(true);

        // used default scope
        $tokenUri = $uriProperty->getValue($credentials);
        $this->assertStringContainsString('a-default-scope', $tokenUri);

        $credentials = $googleAuth->makeCredentials([
            'scope' => 'a-user-scope',
            'defaultScope' => 'a-default-scope'
        ]);

        // did not use default scope
        $tokenUri = $uriProperty->getValue($credentials);
        $this->assertStringContainsString('a-user-scope', $tokenUri);
    }

    public function testUserRefreshCredentials()
    {
        putenv('HOME=' . __DIR__ . '/fixtures2');

        $credentials = (new GoogleAuth())->makeCredentials();

        $this->assertInstanceOf(UserRefreshCredentials::class, $credentials);
    }

    public function testServiceAccountCredentialsDoNotUseDefaultScope()
    {
        putenv('HOME=' . __DIR__ . '/fixtures');

        $credentials = (new GoogleAuth())->makeCredentials([
            'defaultScope' => 'a-default-scope',
        ]);
        $this->assertInstanceOf(ServiceAccountCredentials::class, $credentials);

        $authProp = (new ReflectionClass($credentials))->getProperty('oauth2');
        $authProp->setAccessible(true);
        $oauth2 = $authProp->getValue($credentials);

        // used default scope
        $this->assertNull($oauth2->getScope());

        $credentials = (new GoogleAuth())->makeCredentials([
            'scope' => 'a-user-scope',
            'defaultScope' => 'a-default-scope',
        ]);

        $oauth2 = $authProp->getValue($credentials);

        // used user scope
        $this->assertEquals('a-user-scope', $oauth2->getScope());
    }

    public function testComputeCredentialsDefaultScopeArray()
    {
        $jsonTokens = json_encode(['access_token' => 'abc']);
        $httpClient = httpClientWithResponses([
            new Response(200, ['Metadata-Flavor' => 'Google']),
            new Response(200, [], Psr7\stream_for($jsonTokens)),
        ]);

        $googleAuth = new GoogleAuth(['httpClient' => $httpClient]);
        $credentials = $googleAuth->makeCredentials([
            'defaultScope' => ['default-scope-one', 'default-scope-two']
        ]);
        $this->assertInstanceOf(ComputeCredentials::class, $credentials);
        $uriProperty = (new ReflectionClass($credentials))->getProperty('tokenUri');
        $uriProperty->setAccessible(true);
        $tokenUri = $uriProperty->getValue($credentials);

        // used default scope
        $this->assertStringContainsString(
            'default-scope-one,default-scope-two',
            $tokenUri
        );
    }


    // TODO: Refactor Middleware Tests
    // /**
    //  * @expectedException DomainException
    //  */
    // public function testIsFailsEnvSpecifiesNonExistentFile()
    // {
    //     $keyFile = __DIR__ . '/fixtures' . '/does-not-exist-private.json';
    //     putenv('GOOGLE_APPLICATION_CREDENTIALS=' . $keyFile);
    //     GoogleAuth::getMiddleware('a scope');
    // }

    // public function testLoadsOKIfEnvSpecifiedIsValid()
    // {
    //     $keyFile = __DIR__ . '/fixtures' . '/private.json';
    //     putenv('GOOGLE_APPLICATION_CREDENTIALS=' . $keyFile);
    //     $this->assertNotNull(GoogleAuth::getMiddleware('a scope'));
    // }

    // public function testLoadsDefaultFileIfPresentAndEnvVarIsNotSet()
    // {
    //     putenv('HOME=' . __DIR__ . '/fixtures');
    //     $this->assertNotNull(GoogleAuth::getMiddleware('a scope'));
    // }

    // /**
    //  * @expectedException DomainException
    //  */
    // public function testFailsIfNotOnComputeAndNoDefaultFileFound()
    // {
    //     putenv('HOME=' . __DIR__ . '/not_exist_fixtures');

    //     // simulate not being GCE and retry attempts by returning multiple 500s
    //     $httpClient = httpClientWithResponses([
    //         new Response(500),
    //         new Response(500),
    //         new Response(500)
    //     ]);

    //     GoogleAuth::getMiddleware('a scope', $httpClient);
    // }

    // public function testWithCacheOptions()
    // {
    //     $keyFile = __DIR__ . '/fixtures' . '/private.json';
    //     putenv('GOOGLE_APPLICATION_CREDENTIALS=' . $keyFile);

    //     $httpClient = httpClientWithResponses([
    //         new Response(200),
    //     ]);

    //     $cacheOptions = [];
    //     $cachePool = $this->prophesize(CacheItemPoolInterface::class);

    //     $middleware = GoogleAuth::getMiddleware(
    //         'a scope',
    //         $httpClient,
    //         $cacheOptions,
    //         $cachePool->reveal()
    //     );
    // }

    // public function testSuccedsIfNoDefaultFilesButIsOnCompute()
    // {
    //     $wantedTokens = [
    //         'access_token' => '1/abdef1234567890',
    //         'expires_in' => '57',
    //         'token_type' => 'Bearer',
    //     ];
    //     $jsonTokens = json_encode($wantedTokens);

    //     // simulate the response from GCE.
    //     $httpClient = httpClientWithResponses([
    //         new Response(200, ['Metadata-Flavor' => 'Google']),
    //         new Response(200, [], Psr7\stream_for($jsonTokens)),
    //     ]);

    //     $googleAuth = new GoogleAuth(['httpClient' => $httpClient]);
    //     $client = $googleAuth->makeHttpClient('a scope');

    //     $this->assertNotNull($client);
    // }

    // /**
    //  * @expectedException DomainException
    //  */
    // public function testOnComputeCacheWithHit()
    // {
    //     putenv('HOME=' . __DIR__ . '/not_exist_fixtures');

    //     $mockCacheItem = $this->prophesize(CacheItemInterface::class);
    //     $mockCacheItem->isHit()
    //         ->willReturn(true);
    //     $mockCacheItem->get()
    //         ->shouldBeCalledTimes(1)
    //         ->willReturn(false);

    //     $mockCache = $this->prophesize(CacheItemPoolInterface::class);
    //     $mockCache->getItem('google_auth_on_gce_cache')
    //         ->shouldBeCalledTimes(1)
    //         ->willReturn($mockCacheItem->reveal());

    //     ApplicationDefaultCredentials::getMiddleware(
    //         'a scope',
    //         null,
    //         null,
    //         $mockCache->reveal()
    //     );
    // }

    // public function testOnComputeCacheWithoutHit()
    // {
    //     putenv('HOME=' . __DIR__ . '/not_exist_fixtures');

    //     $gceIsCalled = false;
    //     $dummyHandler = function ($request) use (&$gceIsCalled) {
    //         $gceIsCalled = true;
    //         return new Response(200, ['Metadata-Flavor' => 'Google']);
    //     };
    //     $mockCacheItem = $this->prophesize(CacheItemInterface::class);
    //     $mockCacheItem->isHit()
    //         ->willReturn(false);
    //     $mockCacheItem->set(true)
    //         ->shouldBeCalledTimes(1);
    //     $mockCacheItem->expiresAfter(1500)
    //         ->shouldBeCalledTimes(1);

    //     $mockCache = $this->prophesize(CacheItemPoolInterface::class);
    //     $mockCache->getItem('google_auth_on_gce_cache')
    //         ->shouldBeCalledTimes(1)
    //         ->willReturn($mockCacheItem->reveal());
    //     $mockCache->save($mockCacheItem->reveal())
    //         ->shouldBeCalled();

    //     $credentials = ApplicationDefaultCredentials::getMiddleware(
    //         'a scope',
    //         $dummyHandler,
    //         null,
    //         $mockCache->reveal()
    //     );

    //     $this->assertTrue($gceIsCalled);
    // }

    // public function testOnComputeCacheWithOptions()
    // {
    //     putenv('HOME=' . __DIR__ . '/not_exist_fixtures');

    //     $prefix = 'test_prefix_';
    //     $lifetime = '70707';

    //     $gceIsCalled = false;
    //     $dummyHandler = function ($request) use (&$gceIsCalled) {
    //         $gceIsCalled = true;
    //         return new Response(200, ['Metadata-Flavor' => 'Google']);
    //     };
    //     $mockCacheItem = $this->prophesize(CacheItemInterface::class);
    //     $mockCacheItem->isHit()
    //         ->willReturn(false);
    //     $mockCacheItem->set(true)
    //         ->shouldBeCalledTimes(1);
    //     $mockCacheItem->expiresAfter($lifetime)
    //         ->shouldBeCalledTimes(1);

    //     $mockCache = $this->prophesize(CacheItemPoolInterface::class);
    //     $mockCache->getItem($prefix . 'google_auth_on_gce_cache')
    //         ->shouldBeCalledTimes(1)
    //         ->willReturn($mockCacheItem->reveal());
    //     $mockCache->save($mockCacheItem->reveal())
    //         ->shouldBeCalled();

    //     $credentials = ApplicationDefaultCredentials::getMiddleware(
    //         'a scope',
    //         $dummyHandler,
    //         ['gce_prefix' => $prefix, 'gce_lifetime' => $lifetime],
    //         $mockCache->reveal()
    //     );

    //     $this->assertTrue($gceIsCalled);
    // }

    // /**
    //  * @expectedException DomainException
    //  */
    // public function testIsFailsEnvSpecifiesNonExistentFile()
    // {
    //     $keyFile = __DIR__ . '/fixtures' . '/does-not-exist-private.json';
    //     putenv('GOOGLE_APPLICATION_CREDENTIALS=' . $keyFile);
    //     GoogleAuth::getIdTokenCredentials(self::TEST_TARGET_AUDIENCE);
    // }

    // public function testLoadsOKIfEnvSpecifiedIsValid()
    // {
    //     $keyFile = __DIR__ . '/fixtures' . '/private.json';
    //     putenv('GOOGLE_APPLICATION_CREDENTIALS=' . $keyFile);
    //     GoogleAuth::getIdTokenCredentials(self::TEST_TARGET_AUDIENCE);
    // }

    // public function testLoadsDefaultFileIfPresentAndEnvVarIsNotSet()
    // {
    //     putenv('HOME=' . __DIR__ . '/fixtures');
    //     GoogleAuth::getIdTokenCredentials(self::TEST_TARGET_AUDIENCE);
    // }

    // /**
    //  * @expectedException DomainException
    //  */
    // public function testFailsIfNotOnGceAndNoDefaultFileFound()
    // {
    //     putenv('HOME=' . __DIR__ . '/not_exist_fixtures');

    //     // simulate not being GCE and retry attempts by returning multiple 500s
    //     $httpClient = httpClientWithResponses([
    //         new Response(500),
    //         new Response(500),
    //         new Response(500)
    //     ]);

    //     GoogleAuth::getIdTokenCredentials(
    //         self::TEST_TARGET_AUDIENCE,
    //         $httpClient
    //     );
    // }

    // public function testWithCacheOptions()
    // {
    //     $keyFile = __DIR__ . '/fixtures' . '/private.json';
    //     putenv('GOOGLE_APPLICATION_CREDENTIALS=' . $keyFile);

    //     $httpClient = httpClientWithResponses([
    //         new Response(200),
    //     ]);

    //     $cacheOptions = [];
    //     $cachePool = $this->prophesize(CacheItemPoolInterface::class);

    //     $credentials = GoogleAuth::getIdTokenCredentials(
    //         self::TEST_TARGET_AUDIENCE,
    //         $httpClient,
    //         $cacheOptions,
    //         $cachePool->reveal()
    //     );

    //     $this->assertInstanceOf('Google\Auth\FetchAuthTokenCache', $credentials);
    // }

    // public function testIdTokenIfNoDefaultFilesButIsOnCompute()
    // {
    //     putenv('HOME=' . __DIR__ . '/not_exist_fixtures');
    //     $wantedTokens = [
    //         'access_token' => '1/abdef1234567890',
    //         'expires_in' => '57',
    //         'token_type' => 'Bearer',
    //     ];
    //     $jsonTokens = json_encode($wantedTokens);

    //     // simulate the response from GCE.
    //     $httpClient = httpClientWithResponses([
    //         new Response(200, ['Metadata-Flavor' => 'Google']),
    //         new Response(200, [], Psr7\stream_for($jsonTokens)),
    //     ]);

    //     $credentials = GoogleAuth::getIdTokenCredentials(
    //         self::TEST_TARGET_AUDIENCE,
    //         $httpClient
    //     );

    //     $this->assertInstanceOf(
    //         ComputeCredentials::class,
    //         $credentials
    //     );
    // }

    public function testWithServiceAccountCredentialsAndExplicitQuotaProject()
    {
        $keyFile = __DIR__ . '/fixtures' . '/private.json';
        putenv('GOOGLE_APPLICATION_CREDENTIALS=' . $keyFile);

        $credentials = (new GoogleAuth())->makeCredentials([
            'quotaProject' => self::TEST_QUOTA_PROJECT
        ]);
        $this->assertInstanceOf(ServiceAccountCredentials::class, $credentials);

        $this->assertEquals(
            self::TEST_QUOTA_PROJECT,
            $credentials->getQuotaProject()
        );
    }

    public function testGetCredentialsUtilizesQuotaProjectInKeyFile()
    {
        $keyFile = __DIR__ . '/fixtures' . '/private.json';
        putenv('GOOGLE_APPLICATION_CREDENTIALS=' . $keyFile);

        $credentials = (new GoogleAuth())->makeCredentials();

        $this->assertEquals(
            'test_quota_project',
            $credentials->getQuotaProject()
        );
    }

    public function testWithFetchAuthTokenCacheAndExplicitQuotaProject()
    {
        $keyFile = __DIR__ . '/fixtures' . '/private.json';
        putenv('GOOGLE_APPLICATION_CREDENTIALS=' . $keyFile);

        $httpClient = httpClientWithResponses([
            new Response(200),
        ]);

        $cachePool = $this->prophesize(CacheItemPoolInterface::class);

        $googleAuth = new GoogleAuth([
            'cache' => $cachePool->reveal(),
            'httpClient' => $httpClient,
        ]);

        $credentials = $googleAuth->makeCredentials([
            'quotaProject' => self::TEST_QUOTA_PROJECT
        ]);

        $this->assertInstanceOf(ServiceAccountCredentials::class, $credentials);

        $this->assertEquals(
            self::TEST_QUOTA_PROJECT,
            $credentials->getQuotaProject()
        );
    }

    public function testWithComputeCredentials()
    {
        putenv('HOME=' . __DIR__ . '/not_exist_fixtures');
        $wantedTokens = [
            'access_token' => '1/abdef1234567890',
            'expires_in' => '57',
            'token_type' => 'Bearer',
        ];
        $jsonTokens = json_encode($wantedTokens);

        // simulate the response from GCE.
        $httpClient = httpClientWithResponses([
            new Response(200, ['Metadata-Flavor' => 'Google']),
            new Response(200, [], Psr7\stream_for($jsonTokens)),
        ]);

        $googleAuth = new GoogleAuth([
            'httpClient' => $httpClient
        ]);
        $credentials = $googleAuth->makeCredentials([
            'quotaProject' => self::TEST_QUOTA_PROJECT,
        ]);

        $this->assertInstanceOf(ComputeCredentials::class, $credentials);

        $this->assertEquals(
            self::TEST_QUOTA_PROJECT,
            $credentials->getQuotaProject()
        );
    }

    // START ADCGetCredentialsAppEngineTest

    public function testAppEngineFlexible()
    {
        $_SERVER['SERVER_SOFTWARE'] = 'Google App Engine';
        putenv('GAE_INSTANCE=aef-default-20180313t154438');
        $httpClient = httpClientWithResponses([
            new Response(200, ['Metadata-Flavor' => 'Google']),
        ]);
        $googleAuth = new GoogleAuth([
            'httpClient' => $httpClient
        ]);
        $this->assertInstanceOf(
            ComputeCredentials::class,
            $googleAuth->makeCredentials()
        );
    }

    public function testAppEngineFlexibleIdToken()
    {
        $_SERVER['SERVER_SOFTWARE'] = 'Google App Engine';
        putenv('GAE_INSTANCE=aef-default-20180313t154438');
        $httpClient = httpClientWithResponses([
            new Response(200, ['Metadata-Flavor' => 'Google']),
        ]);
        $googleAuth = new GoogleAuth(['httpClient' => $httpClient]);
        $credentials = $googleAuth->makeCredentials([
            'targetAudience' => self::TEST_TARGET_AUDIENCE,
        ]);
        $this->assertInstanceOf(ComputeCredentials::class, $credentials);
        $uriProperty = (new ReflectionClass($credentials))->getProperty('tokenUri');
        $uriProperty->setAccessible(true);
        $tokenUri = $uriProperty->getValue($credentials);
        $this->assertStringContainsString('/identity', $tokenUri);
        $this->assertStringContainsString(self::TEST_TARGET_AUDIENCE, $tokenUri);

    }

    // START GoogleAuthFetchCertsTest

    public function testGetCertsForIap()
    {
        $iapJwkUrl = 'https://www.gstatic.com/iap/verify/public_key-jwk';
        $googleAuth = new GoogleAuth();
        $reflector = new \ReflectionClass($googleAuth);
        $getCertsMethod = $reflector->getMethod('getCerts');
        $getCertsMethod->setAccessible(true);
        $cacheKey = 'test_cache_key';
        $certs = $getCertsMethod->invoke(
            $googleAuth,
            $iapJwkUrl,
            $cacheKey
        );

        $this->assertTrue(is_array($certs));
        $this->assertEquals(5, count($certs['keys']));
    }

    public function testRetrieveCertsFromLocationLocalFile()
    {
        $certsLocation = __DIR__ . '/fixtures/federated-certs.json';
        $certsData = json_decode(file_get_contents($certsLocation), true);
        $parsedCertsData = [];

        $item = $this->prophesize(CacheItemInterface::class);
        $item->get()
            ->shouldBeCalledTimes(1)
            ->willReturn(null);
        $item->set($certsData)
            ->shouldBeCalledTimes(1);
        $item->expiresAfter(Argument::type('int'))
            ->shouldBeCalledTimes(1);

        $this->mockCache->getItem('google_auth_certs_cache|' . sha1($certsLocation))
            ->shouldBeCalledTimes(1)
            ->willReturn($item->reveal());

        $this->mockCache->save(Argument::type(CacheItemInterface::class))
            ->shouldBeCalledTimes(1);

        $jwt = $this->prophesize(JwtClientInterface::class);
        $jwt->parseKeySet($certsData)
            ->shouldBeCalledTimes(1)
            ->willReturn($parsedCertsData);
        $jwt->decode(self::TEST_TOKEN, $parsedCertsData, ['RS256'])
            ->shouldBeCalledTimes(1)
            ->willReturn([
                'iss' => 'https://accounts.google.com'
            ]);

        $googleAuth = new GoogleAuth([
            'cache' => $this->mockCache->reveal(),
            'jwtClient' => $jwt->reveal(),
        ]);

        $this->assertTrue($googleAuth->verify(self::TEST_TOKEN, [
            'certsLocation' => $certsLocation
        ]));
    }

    public function testRetrieveCertsFromLocationLocalFileInvalidFilePath()
    {
        $this->expectException('InvalidArgumentException');
        $this->expectExceptionMessage('Failed to retrieve verification certificates from path');

        $certsLocation = __DIR__ . '/fixtures/federated-certs-does-not-exist.json';

        $item = $this->prophesize(CacheItemInterface::class);
        $item->get()
            ->shouldBeCalledTimes(1)
            ->willReturn(null);

        $this->mockCache->getItem('google_auth_certs_cache|' . sha1($certsLocation))
            ->shouldBeCalledTimes(1)
            ->willReturn($item->reveal());

        $googleAuth = new GoogleAuth(['cache' => $this->mockCache->reveal()]);

        $googleAuth->verify(self::TEST_TOKEN, [
            'certsLocation' => $certsLocation
        ]);
    }

    public function testRetrieveCertsInvalidData()
    {
        $this->expectException('InvalidArgumentException');
        $this->expectExceptionMessage('certs expects "keys" to be set');

        $item = $this->prophesize(CacheItemInterface::class);
        $item->get()
            ->shouldBeCalledTimes(1)
            ->willReturn('{}');

        $this->mockCache->getItem('google_auth_certs_cache|' . self::OIDC_CERTS_HASH)
            ->shouldBeCalledTimes(1)
            ->willReturn($item->reveal());

        $googleAuth = new GoogleAuth(['cache' => $this->mockCache->reveal()]);

        $googleAuth->verify(self::TEST_TOKEN);
    }

    public function testRetrieveCertsFromLocationLocalFileInvalidFileData()
    {
        $this->expectException('InvalidArgumentException');
        $this->expectExceptionMessage('certs expects "keys" to be set');

        $temp = tmpfile();
        fwrite($temp, '{}');
        $certsLocation = stream_get_meta_data($temp)['uri'];

        $item = $this->prophesize(CacheItemInterface::class);
        $item->get()
            ->shouldBeCalledTimes(1)
            ->willReturn(null);

        $this->mockCache->getItem('google_auth_certs_cache|' . sha1($certsLocation))
            ->shouldBeCalledTimes(1)
            ->willReturn($item->reveal());

        $googleAuth = new GoogleAuth(['cache' => $this->mockCache->reveal()]);

        $googleAuth->verify(self::TEST_TOKEN, [
            'certsLocation' => $certsLocation
        ]);
    }

    public function testRetrieveCertsFromLocationRemote()
    {
        $certsLocation = __DIR__ . '/fixtures/federated-certs.json';
        $certsJson = file_get_contents($certsLocation);
        $certsData = json_decode($certsJson, true);
        $parsedCertsData = [];

        $httpClient = httpClientFromCallable(
            function ($request) use ($certsJson) {
                $this->assertEquals(
                    'https://www.googleapis.com/oauth2/v3/certs',
                    (string) $request->getUri()
                );
                $this->assertEquals('GET', $request->getMethod());

                return new Response(200, [], $certsJson);
            }
        );

        $item = $this->prophesize(CacheItemInterface::class);
        $item->get()
            ->shouldBeCalledTimes(1)
            ->willReturn(null);
        $item->set($certsData)
            ->shouldBeCalledTimes(1);
        $item->expiresAfter(1500)
            ->shouldBeCalledTimes(1);

        $this->mockCache->getItem('google_auth_certs_cache|' . self::OIDC_CERTS_HASH)
            ->shouldBeCalledTimes(1)
            ->willReturn($item->reveal());

        $this->mockCache->save(Argument::type(CacheItemInterface::class))
            ->shouldBeCalledTimes(1);

        $jwt = $this->prophesize(JwtClientInterface::class);
        $jwt->parseKeySet($certsData)
            ->shouldBeCalledTimes(1)
            ->willReturn($parsedCertsData);
        $jwt->decode(self::TEST_TOKEN, $parsedCertsData, ['RS256'])
            ->shouldBeCalledTimes(1)
            ->willReturn([
                'iss' => 'https://accounts.google.com'
            ]);

        $googleAuth = new GoogleAuth([
            'cache' => $this->mockCache->reveal(),
            'httpClient' => $httpClient,
            'jwtClient' => $jwt->reveal(),
        ]);

        $this->assertTrue($googleAuth->verify(self::TEST_TOKEN));
    }

    public function testRetrieveCertsFromLocationRemoteBadRequest()
    {
        $this->expectException('RuntimeException');
        $this->expectExceptionMessage('bad news guys');

        $badBody = 'bad news guys';

        $httpClient = httpClientWithResponses([
            new Response(500, [], $badBody),
        ]);

        $item = $this->prophesize(CacheItemInterface::class);
        $item->get()
            ->shouldBeCalledTimes(1)
            ->willReturn(null);

        $this->mockCache->getItem('google_auth_certs_cache|' . self::OIDC_CERTS_HASH)
            ->shouldBeCalledTimes(1)
            ->willReturn($item->reveal());

        $googleAuth = new GoogleAuth([
            'httpClient' => $httpClient,
            'cache' => $this->mockCache->reveal()
        ]);

        $googleAuth->verify(self::TEST_TOKEN);
    }
}
