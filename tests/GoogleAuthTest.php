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
use Google\Auth\GCECache;
use GuzzleHttp\Psr7;
use PHPUnit\Framework\TestCase;
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

    private $mockCacheItem;
    private $mockCache;

    protected function setUp(): void
    {
        putenv('HOME');
        putenv('GOOGLE_APPLICATION_CREDENTIALS');
        $this->mockCacheItem = $this->prophesize('Psr\Cache\CacheItemInterface');
        $this->mockCache = $this->prophesize('Psr\Cache\CacheItemPoolInterface');
    }

    public function testCachedOnGceTrueValue()
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

    public function testCachedOnGceFalseValue()
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

    public function testUncached()
    {
        $gceIsCalled = false;
        $dummyHandler = function ($request) use (&$gceIsCalled) {
            $gceIsCalled = true;
            return new Psr7\Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']);
        };

        $this->mockCacheItem->isHit()
            ->shouldBeCalledTimes(1)
            ->willReturn(false);
        $this->mockCacheItem->set(true)
            ->shouldBeCalledTimes(1);
        $this->mockCacheItem->expiresAfter(1500)
            ->shouldBeCalledTimes(1);
        $this->mockCache->getItem('google_auth_on_gce_cache')
            ->shouldBeCalledTimes(2)
            ->willReturn($this->mockCacheItem->reveal());
        $this->mockCache->save($this->mockCacheItem->reveal())
            ->shouldBeCalledTimes(1);

        // Run the test.
        $googleAuth = new GoogleAuth(['cache' => $this->mockCache->reveal()]);

        $this->assertTrue($googleAuth->onCompute($dummyHandler));
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
        $dummyHandler = function ($request) use (&$gceIsCalled) {
            $gceIsCalled = true;
            return new Psr7\Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']);
        };
        $this->mockCacheItem->isHit()
            ->willReturn(false);
        $this->mockCacheItem->set(true)
            ->shouldBeCalledTimes(1);
        $this->mockCacheItem->expiresAfter($lifetime)
            ->shouldBeCalledTimes(1);
        $this->mockCache->getItem($prefix . 'google_auth_on_gce_cache')
            ->shouldBeCalledTimes(2)
            ->willReturn($this->mockCacheItem->reveal());
        $this->mockCache->save($this->mockCacheItem->reveal())
            ->shouldBeCalled();

        // Run the test
        $googleAuth = new GoogleAuth([
            'cachePrefix' => $prefix,
            'cacheLifetime' => $lifetime,
            'cache' => $this->mockCache->reveal(),
            'httpClient' => createHttpClient($dummyHandler),
        ]);
        $onCompute = $googleAuth->onCompute();
        $this->assertTrue($onCompute);
        $this->assertTrue($gceIsCalled);
    }

    /**
     * @expectedException DomainException
     */
    public function testIsFailsEnvSpecifiesNonExistentFile()
    {
        putenv('HOME');
        $keyFile = __DIR__ . '/fixtures' . '/does-not-exist-private.json';
        putenv('GOOGLE_APPLICATION_CREDENTIALS=' . $keyFile);
        (new GoogleAuth())->makeCredentials(['scope' => 'a scope']);
    }

    public function testLoadsOKIfEnvSpecifiedIsValid()
    {
        putenv('HOME');
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

    /**
     * @expectedException DomainException
     */
    public function testFailsIfNotOnGceAndNoDefaultFileFound()
    {
        putenv('HOME=' . __DIR__ . '/not_exist_fixtures');
        // simulate not being GCE and retry attempts by returning multiple 500s
        $httpHandler = getHandler([
            buildResponse(500),
            buildResponse(500),
            buildResponse(500)
        ]);
        $googleAuth = new GoogleAuth([
            'httpClient' => createHttpClient($httpHandler),
        ]);
        $googleAuth->makeCredentials(['scope' => 'a scope']);
    }

    public function testSuccedsIfNoDefaultFilesButIsOnCompute()
    {
        putenv('HOME');

        $wantedTokens = [
            'access_token' => '1/abdef1234567890',
            'expires_in' => '57',
            'token_type' => 'Bearer',
        ];
        $jsonTokens = json_encode($wantedTokens);

        // simulate the response from GCE.
        $httpHandler = getHandler([
            buildResponse(200, ['Metadata-Flavor' => 'Google']),
            buildResponse(200, [], Psr7\stream_for($jsonTokens)),
        ]);
        $googleAuth = new GoogleAuth([
            'httpClient' => createHttpClient($httpHandler),
        ]);
        $this->assertNotNull(
            $googleAuth->makeCredentials(['scope' => 'a scope'])
        );
    }

    public function testComputeCredentials()
    {
        putenv('HOME');

        $jsonTokens = json_encode(['access_token' => 'abc']);
        $httpHandler = getHandler([
            buildResponse(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
            buildResponse(200, [], Psr7\stream_for($jsonTokens)),
        ]);
        $googleAuth = new GoogleAuth([
            'httpClient' => createHttpClient($httpHandler),
        ]);
        $creds = $googleAuth->makeCredentials([
            'defaultScope' => 'a+default+scope' // $defaultScope
        ]);

        $this->assertInstanceOf(
            'Google\Auth\Credentials\GCECredentials',
            $creds
        );

        $uriProperty = (new ReflectionClass($creds))->getProperty('tokenUri');
        $uriProperty->setAccessible(true);

        // used default scope
        $tokenUri = $uriProperty->getValue($creds);
        $this->assertContains('a+default+scope', $tokenUri);

        $creds = $googleAuth->makeCredentials([
            'scope' => 'a+user+scope', // $scope
            'defaultScope' => 'a+default+scope' // $defaultScope
        ]);

        // did not use default scope
        $tokenUri = $uriProperty->getValue($creds);
        $this->assertContains('a+user+scope', $tokenUri);
    }

    public function testUserRefreshCredentials()
    {
        putenv('HOME=' . __DIR__ . '/fixtures2');

        $googleAuth = new GoogleAuth();
        $creds = $googleAuth->makeCredentials([
            'defaultScope' => 'a default scope',
        ]);

        $this->assertInstanceOf(
            'Google\Auth\Credentials\UserRefreshCredentials',
            $creds
        );

        $authProperty = (new ReflectionClass($creds))->getProperty('auth');
        $authProperty->setAccessible(true);

        // used default scope
        $auth = $authProperty->getValue($creds);
        $this->assertEquals('a default scope', $auth->getScope());

        $creds = $googleAuth->makeCredentials([
            'scope' => 'a user scope',
            'defaultScope' => 'a default scope',
        ]);

        // did not use default scope
        $auth = $authProperty->getValue($creds);
        $this->assertEquals('a user scope', $auth->getScope());
    }

    public function testServiceAccountCredentials()
    {
        putenv('HOME=' . __DIR__ . '/fixtures');

        $googleAuth = new GoogleAuth();
        $creds = $googleAuth->makeCredentials([
            'defaultScope' => 'a default scope',
        ]);

        $this->assertInstanceOf(
            'Google\Auth\Credentials\ServiceAccountCredentials',
            $creds
        );

        $authProperty = (new ReflectionClass($creds))->getProperty('auth');
        $authProperty->setAccessible(true);

        // did not use default scope
        $auth = $authProperty->getValue($creds);
        $this->assertEquals('', $auth->getScope());

        $creds = $googleAuth->makeCredentials([
            'scope' => 'a user scope',
            'defaultScope' => 'a default scope',
        ]);

        // used user scope
        $auth = $authProperty->getValue($creds);
        $this->assertEquals('a user scope', $auth->getScope());
    }

    public function testDefaultScopeArray()
    {
        putenv('HOME=' . __DIR__ . '/fixtures2');

        $creds = (new GoogleAuth())->makeCredentials([
            'defaultScope' => ['onescope', 'twoscope'] // $defaultScope
        ]);

        $authProperty = (new ReflectionClass($creds))->getProperty('auth');
        $authProperty->setAccessible(true);

        // used default scope
        $auth = $authProperty->getValue($creds);
        $this->assertEquals('onescope twoscope', $auth->getScope());
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
    //     $httpHandler = getHandler([
    //         buildResponse(500),
    //         buildResponse(500),
    //         buildResponse(500)
    //     ]);

    //     GoogleAuth::getMiddleware('a scope', $httpHandler);
    // }

    // public function testWithCacheOptions()
    // {
    //     $keyFile = __DIR__ . '/fixtures' . '/private.json';
    //     putenv('GOOGLE_APPLICATION_CREDENTIALS=' . $keyFile);

    //     $httpHandler = getHandler([
    //         buildResponse(200),
    //     ]);

    //     $cacheOptions = [];
    //     $cachePool = $this->prophesize('Psr\Cache\CacheItemPoolInterface');

    //     $middleware = GoogleAuth::getMiddleware(
    //         'a scope',
    //         $httpHandler,
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
    //     $httpHandler = getHandler([
    //         buildResponse(200, ['Metadata-Flavor' => 'Google']),
    //         buildResponse(200, [], Psr7\stream_for($jsonTokens)),
    //     ]);

    //     $googleAuth = new GoogleAuth(['httpHandler' => $httpHandler]);
    //     $client = $googleAuth->makeHttpClient('a scope');

    //     $this->assertNotNull($client);
    // }

    // /**
    //  * @expectedException DomainException
    //  */
    // public function testOnComputeCacheWithHit()
    // {
    //     putenv('HOME=' . __DIR__ . '/not_exist_fixtures');

    //     $mockCacheItem = $this->prophesize('Psr\Cache\CacheItemInterface');
    //     $mockCacheItem->isHit()
    //         ->willReturn(true);
    //     $mockCacheItem->get()
    //         ->shouldBeCalledTimes(1)
    //         ->willReturn(false);

    //     $mockCache = $this->prophesize('Psr\Cache\CacheItemPoolInterface');
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
    //         return new Psr7\Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']);
    //     };
    //     $mockCacheItem = $this->prophesize('Psr\Cache\CacheItemInterface');
    //     $mockCacheItem->isHit()
    //         ->willReturn(false);
    //     $mockCacheItem->set(true)
    //         ->shouldBeCalledTimes(1);
    //     $mockCacheItem->expiresAfter(1500)
    //         ->shouldBeCalledTimes(1);

    //     $mockCache = $this->prophesize('Psr\Cache\CacheItemPoolInterface');
    //     $mockCache->getItem('google_auth_on_gce_cache')
    //         ->shouldBeCalledTimes(2)
    //         ->willReturn($mockCacheItem->reveal());
    //     $mockCache->save($mockCacheItem->reveal())
    //         ->shouldBeCalled();

    //     $creds = ApplicationDefaultCredentials::getMiddleware(
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
    //         return new Psr7\Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']);
    //     };
    //     $mockCacheItem = $this->prophesize('Psr\Cache\CacheItemInterface');
    //     $mockCacheItem->isHit()
    //         ->willReturn(false);
    //     $mockCacheItem->set(true)
    //         ->shouldBeCalledTimes(1);
    //     $mockCacheItem->expiresAfter($lifetime)
    //         ->shouldBeCalledTimes(1);

    //     $mockCache = $this->prophesize('Psr\Cache\CacheItemPoolInterface');
    //     $mockCache->getItem($prefix . 'google_auth_on_gce_cache')
    //         ->shouldBeCalledTimes(2)
    //         ->willReturn($mockCacheItem->reveal());
    //     $mockCache->save($mockCacheItem->reveal())
    //         ->shouldBeCalled();

    //     $creds = ApplicationDefaultCredentials::getMiddleware(
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
    //     putenv('HOME');
    //     $keyFile = __DIR__ . '/fixtures' . '/does-not-exist-private.json';
    //     putenv('GOOGLE_APPLICATION_CREDENTIALS=' . $keyFile);
    //     GoogleAuth::getIdTokenCredentials(self::TEST_TARGET_AUDIENCE);
    // }

    // public function testLoadsOKIfEnvSpecifiedIsValid()
    // {
    //     putenv('HOME');
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
    //     $httpHandler = getHandler([
    //         buildResponse(500),
    //         buildResponse(500),
    //         buildResponse(500)
    //     ]);

    //     GoogleAuth::getIdTokenCredentials(
    //         self::TEST_TARGET_AUDIENCE,
    //         $httpHandler
    //     );
    // }

    // public function testWithCacheOptions()
    // {
    //     putenv('HOME');
    //     $keyFile = __DIR__ . '/fixtures' . '/private.json';
    //     putenv('GOOGLE_APPLICATION_CREDENTIALS=' . $keyFile);

    //     $httpHandler = getHandler([
    //         buildResponse(200),
    //     ]);

    //     $cacheOptions = [];
    //     $cachePool = $this->prophesize('Psr\Cache\CacheItemPoolInterface');

    //     $credentials = GoogleAuth::getIdTokenCredentials(
    //         self::TEST_TARGET_AUDIENCE,
    //         $httpHandler,
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
    //     $httpHandler = getHandler([
    //         buildResponse(200, ['Metadata-Flavor' => 'Google']),
    //         buildResponse(200, [], Psr7\stream_for($jsonTokens)),
    //     ]);

    //     $credentials = GoogleAuth::getIdTokenCredentials(
    //         self::TEST_TARGET_AUDIENCE,
    //         $httpHandler
    //     );

    //     $this->assertInstanceOf(
    //         'Google\Auth\Credentials\ComputeCredentials',
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

        $this->assertInstanceOf(
            'Google\Auth\Credentials\ServiceAccountCredentials',
            $credentials
        );

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

        $httpHandler = getHandler([
            buildResponse(200),
        ]);

        $cachePool = $this->prophesize('Psr\Cache\CacheItemPoolInterface');

        $googleAuth = new GoogleAuth([
            'cache' => $cachePool->reveal(),
            'httpClient' => createHttpClient($httpHandler),
        ]);

        $credentials = $googleAuth->makeCredentials([
            'quotaProject' => self::TEST_QUOTA_PROJECT
        ]);

        $this->assertInstanceOf('Google\Auth\FetchAuthTokenCache', $credentials);

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
        $httpHandler = getHandler([
            buildResponse(200, ['Metadata-Flavor' => 'Google']),
            buildResponse(200, [], Psr7\stream_for($jsonTokens)),
        ]);

        $googleAuth = new GoogleAuth([
            'httpClient' => createHttpClient($httpHandler),
        ]);
        $credentials = $googleAuth->makeCredentials([
            'quotaProject' => self::TEST_QUOTA_PROJECT,
        ]);

        $this->assertInstanceOf(
            'Google\Auth\Credentials\ComputeCredentials',
            $credentials
        );

        $this->assertEquals(
            self::TEST_QUOTA_PROJECT,
            $credentials->getQuotaProject()
        );
    }

    // START ADCGetCredentialsAppEngineTest

    public function testAppEngineStandard()
    {
        $_SERVER['SERVER_SOFTWARE'] = 'Google App Engine';
        $this->assertInstanceOf(
            'Google\Auth\Credentials\AppIdentityCredentials',
            (new GoogleAuth())->makeCredentials()
        );
    }

    public function testAppEngineFlexible()
    {
        $_SERVER['SERVER_SOFTWARE'] = 'Google App Engine';
        putenv('GAE_INSTANCE=aef-default-20180313t154438');
        $httpHandler = getHandler([
            buildResponse(200, ['Metadata-Flavor' => 'Google']),
        ]);
        $googleAuth = new GoogleAuth([
            'httpClient' => createHttpClient($httpHandler)
        ]);
        $this->assertInstanceOf(
            'Google\Auth\Credentials\ComputeCredentials',
            $googleAuth->makeCredentials()
        );
    }

    public function testAppEngineFlexibleIdToken()
    {
        $_SERVER['SERVER_SOFTWARE'] = 'Google App Engine';
        putenv('GAE_INSTANCE=aef-default-20180313t154438');
        $httpHandler = getHandler([
            buildResponse(200, ['Metadata-Flavor' => 'Google']),
        ]);
        $creds = GoogleAuth::getIdTokenCredentials(
            self::TEST_TARGET_AUDIENCE,
            $httpHandler
        );
        $this->assertInstanceOf(
            'Google\Auth\Credentials\ComputeCredentials',
            $creds
        );
    }

    // START GoogleAuthFetchCertsTest

    public function testGetCertsForIap()
    {
        $googleAuth = new GoogleAuth();
        $reflector = new \ReflectionObject($googleAuth);
        $cacheKeyMethod = $reflector->getMethod('getCacheKeyFromCertLocation');
        $cacheKeyMethod->setAccessible(true);
        $getCertsMethod = $reflector->getMethod('getCerts');
        $getCertsMethod->setAccessible(true);
        $cacheKey = $cacheKeyMethod->invoke($googleAuth, GoogleAuth::IAP_CERT_URL);
        $certs = $getCertsMethod->invoke(
            $googleAuth,
            GoogleAuth::IAP_CERT_URL,
            $cacheKey
        );
        $this->assertTrue(is_array($certs));
        $this->assertEquals(5, count($certs));
    }

    public function testRetrieveCertsFromLocationLocalFile()
    {
        $certsLocation = __DIR__ . '/fixtures/federated-certs.json';
        $certsData = json_decode(file_get_contents($certsLocation), true);

        $item = $this->prophesize('Psr\Cache\CacheItemInterface');
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

        $this->mockCache->save(Argument::type('Psr\Cache\CacheItemInterface'))
            ->shouldBeCalledTimes(1);

        $googleAuth = new GoogleAuth(['cache' => $this->mockCache->reveal()]);

        $googleAuth->mocks['decode'] = function ($googleAuth, $publicKey, $allowedAlgs) {
            $this->assertEquals(self::TEST_TOKEN, $googleAuth);
            $this->assertEquals(['RS256'], $allowedAlgs);

            return (object) [
                'iat' => time(),
                'exp' => time() + 30,
                'name' => 'foo',
                'iss' => AccessToken::OAUTH2_ISSUER_HTTPS
            ];;
        };

        $googleAuth->verify(self::TEST_TOKEN, [
            'certsLocation' => $certsLocation
        ]);
    }

    public function testRetrieveCertsFromLocationLocalFileInvalidFilePath()
    {
        $this->expectException('InvalidArgumentException');
        $this->expectExceptionMessage('Failed to retrieve verification certificates from path');

        $certsLocation = __DIR__ . '/fixtures/federated-certs-does-not-exist.json';

        $item = $this->prophesize('Psr\Cache\CacheItemInterface');
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
        $this->expectExceptionMessage('federated sign-on certs expects "keys" to be set');

        $item = $this->prophesize('Psr\Cache\CacheItemInterface');
        $item->get()
            ->shouldBeCalledTimes(1)
            ->willReturn('{}');

        $this->mockCache->getItem('google_auth_certs_cache|federated_signon_certs_v3')
            ->shouldBeCalledTimes(1)
            ->willReturn($item->reveal());

        $googleAuth = new GoogleAuth(['cache' => $this->mockCache->reveal()]);

        $googleAuth->verify(self::TEST_TOKEN);
    }

    public function testRetrieveCertsFromLocationLocalFileInvalidFileData()
    {
         $this->expectException('InvalidArgumentException');
         $this->expectExceptionMessage('federated sign-on certs expects "keys" to be set');
        $temp = tmpfile();
        fwrite($temp, '{}');
        $certsLocation = stream_get_meta_data($temp)['uri'];

        $item = $this->prophesize('Psr\Cache\CacheItemInterface');
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

        $httpHandler = function (RequestInterface $request) use ($certsJson) {
            $this->assertEquals(GoogleAuth::FEDERATED_SIGNON_CERT_URL, (string) $request->getUri());
            $this->assertEquals('GET', $request->getMethod());

            return new Response(200, [], $certsJson);
        };

        $item = $this->prophesize('Psr\Cache\CacheItemInterface');
        $item->get()
            ->shouldBeCalledTimes(1)
            ->willReturn(null);
        $item->set($certsData)
            ->shouldBeCalledTimes(1);
        $item->expiresAt(Argument::type('\DateTime'))
            ->shouldBeCalledTimes(1);

        $this->mockCache->getItem('google_auth_certs_cache|federated_signon_certs_v3')
            ->shouldBeCalledTimes(1)
            ->willReturn($item->reveal());

        $this->mockCache->save(Argument::type('Psr\Cache\CacheItemInterface'))
            ->shouldBeCalledTimes(1);

        $googleAuth = new GoogleAuth([
            'httpClient' => createHttpClient($httpHandler),
            'cache' => $this->mockCache->reveal(),
        ]);

        $googleAuth->mocks['decode'] = function ($googleAuth, $publicKey, $allowedAlgs) {
            $this->assertEquals(self::TEST_TOKEN, $googleAuth);
            $this->assertEquals(['RS256'], $allowedAlgs);

            return (object) [
                'iat' => time(),
                'exp' => time() + 30,
                'name' => 'foo',
                'iss' => AccessToken::OAUTH2_ISSUER_HTTPS
            ];;
        };

        $googleAuth->verify(self::TEST_TOKEN);
    }

    public function testRetrieveCertsFromLocationRemoteBadRequest()
    {
        $this->expectException('RuntimeException');
        $this->expectExceptionMessage('bad news guys');

        $badBody = 'bad news guys';

        $httpHandler = function ($request) use ($badBody) {
            return new Response(500, [], $badBody);
        };

        $item = $this->prophesize('Psr\Cache\CacheItemInterface');
        $item->get()
            ->shouldBeCalledTimes(1)
            ->willReturn(null);

        $this->mockCache->getItem('google_auth_certs_cache|federated_signon_certs_v3')
            ->shouldBeCalledTimes(1)
            ->willReturn($item->reveal());

        $googleAuth = new GoogleAuth([
            'httpClient' => createHttpClient($httpHandler),
            'cache' => $this->mockCache->reveal()
        ]);

        $googleAuth->verify(self::TEST_TOKEN);
    }
}
