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
        $googleAuth = new GoogleAuth(
            null,
            $this->mockCache->reveal()
        );
        $this->assertTrue($googleAuth->onGce());
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
        $googleAuth = new GoogleAuth(
            null,
            $this->mockCache->reveal()
        );
        $this->assertFalse($googleAuth->onGce());
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
        $googleAuth = new GoogleAuth(
            null,
            $this->mockCache->reveal()
        );

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
        $gceCache = new GCECache(
            ['prefix' => $prefix, 'lifetime' => $lifetime],
            $this->mockCache->reveal()
        );
        $this->assertTrue($gceCache->onCompute());
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
        $gceCache = new GCECache(
            ['prefix' => $prefix, 'lifetime' => $lifetime],
            $this->mockCache->reveal()
        );
        $onGce = $gceCache->onGce($dummyHandler);
        $this->assertTrue($onGce);
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
        GoogleAuth::getCredentials('a scope');
    }

    public function testLoadsOKIfEnvSpecifiedIsValid()
    {
        putenv('HOME');
        $keyFile = __DIR__ . '/fixtures' . '/private.json';
        putenv('GOOGLE_APPLICATION_CREDENTIALS=' . $keyFile);
        $this->assertNotNull(
            GoogleAuth::getCredentials('a scope')
        );
    }

    public function testLoadsDefaultFileIfPresentAndEnvVarIsNotSet()
    {
        putenv('HOME=' . __DIR__ . '/fixtures');
        $this->assertNotNull(
            GoogleAuth::getCredentials('a scope')
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

        GoogleAuth::getCredentials('a scope', $httpHandler);
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

        $this->assertNotNull(
            GoogleAuth::getCredentials('a scope', $httpHandler)
        );
    }

    public function testComputeCredentials()
    {
        putenv('HOME');

        $jsonTokens = json_encode(['access_token' => 'abc']);

        $creds = GoogleAuth::getCredentials(
            null, // $scope
            $httpHandler = getHandler([
                buildResponse(200, ['Metadata-Flavor' => 'Google']),
                buildResponse(200, [], Psr7\stream_for($jsonTokens)),
            ]), // $httpHandler
            null, // $cacheConfig
            null, // $cache
            null, // $quotaProject
            'a+default+scope' // $defaultScope
        );

        $this->assertInstanceOf(
            'Google\Auth\Credentials\GCECredentials',
            $creds
        );

        $uriProperty = (new ReflectionClass($creds))->getProperty('tokenUri');
        $uriProperty->setAccessible(true);

        // used default scope
        $tokenUri = $uriProperty->getValue($creds);
        $this->assertContains('a+default+scope', $tokenUri);

        $creds = ApplicationDefaultCredentials::getCredentials(
            'a+user+scope', // $scope
            getHandler([
                buildResponse(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
                buildResponse(200, [], Psr7\stream_for($jsonTokens)),
            ]), // $httpHandler
            null, // $cacheConfig
            null, // $cache
            null, // $quotaProject
            'a+default+scope' // $defaultScope
        );

        // did not use default scope
        $tokenUri = $uriProperty->getValue($creds);
        $this->assertContains('a+user+scope', $tokenUri);
    }

    public function testUserRefreshCredentials()
    {
        putenv('HOME=' . __DIR__ . '/fixtures2');

        $creds = ApplicationDefaultCredentials::getCredentials(
            null, // $scope
            null, // $httpHandler
            null, // $cacheConfig
            null, // $cache
            null, // $quotaProject
            'a default scope' // $defaultScope
        );

        $this->assertInstanceOf(
            'Google\Auth\Credentials\UserRefreshCredentials',
            $creds
        );

        $authProperty = (new ReflectionClass($creds))->getProperty('auth');
        $authProperty->setAccessible(true);

        // used default scope
        $auth = $authProperty->getValue($creds);
        $this->assertEquals('a default scope', $auth->getScope());

        $creds = ApplicationDefaultCredentials::getCredentials(
            'a user scope', // $scope
            null, // $httpHandler
            null, // $cacheConfig
            null, // $cache
            null, // $quotaProject
            'a default scope' // $defaultScope
        );

        // did not use default scope
        $auth = $authProperty->getValue($creds);
        $this->assertEquals('a user scope', $auth->getScope());
    }

    public function testServiceAccountCredentials()
    {
        putenv('HOME=' . __DIR__ . '/fixtures');

        $creds = ApplicationDefaultCredentials::getCredentials(
            null, // $scope
            null, // $httpHandler
            null, // $cacheConfig
            null, // $cache
            null, // $quotaProject
            'a default scope' // $defaultScope
        );

        $this->assertInstanceOf(
            'Google\Auth\Credentials\ServiceAccountCredentials',
            $creds
        );

        $authProperty = (new ReflectionClass($creds))->getProperty('auth');
        $authProperty->setAccessible(true);

        // did not use default scope
        $auth = $authProperty->getValue($creds);
        $this->assertEquals('', $auth->getScope());

        $creds = ApplicationDefaultCredentials::getCredentials(
            'a user scope', // $scope
            null, // $httpHandler
            null, // $cacheConfig
            null, // $cache
            null, // $quotaProject
            'a default scope' // $defaultScope
        );

        // used user scope
        $auth = $authProperty->getValue($creds);
        $this->assertEquals('a user scope', $auth->getScope());
    }

    public function testDefaultScopeArray()
    {
        putenv('HOME=' . __DIR__ . '/fixtures2');

        $creds = ApplicationDefaultCredentials::getCredentials(
            null, // $scope
            null, // $httpHandler
            null, // $cacheConfig
            null, // $cache
            null, // $quotaProject
            ['onescope', 'twoscope'] // $defaultScope
        );

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

        $credentials = GoogleAuth::getCredentials(
            null,
            null,
            null,
            null,
            self::TEST_QUOTA_PROJECT
        );

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

        $credentials = ApplicationDefaultCredentials::getCredentials();

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

        $cacheOptions = [];
        $cachePool = $this->prophesize('Psr\Cache\CacheItemPoolInterface');

        $credentials = GoogleAuth::getCredentials(
            null,
            $httpHandler,
            $cacheOptions,
            $cachePool->reveal(),
            self::TEST_QUOTA_PROJECT
        );

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

        $credentials = GoogleAuth::getCredentials(
            null,
            $httpHandler,
            null,
            null,
            self::TEST_QUOTA_PROJECT
        );

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
            GoogleAuth::getCredentials()
        );
    }

    public function testAppEngineFlexible()
    {
        $_SERVER['SERVER_SOFTWARE'] = 'Google App Engine';
        putenv('GAE_INSTANCE=aef-default-20180313t154438');
        $httpHandler = getHandler([
            buildResponse(200, ['Metadata-Flavor' => 'Google']),
        ]);
        $this->assertInstanceOf(
            'Google\Auth\Credentials\ComputeCredentials',
            GoogleAuth::getCredentials(null, $httpHandler)
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
        $token = new GoogleAuth();
        $reflector = new \ReflectionObject($token);
        $cacheKeyMethod = $reflector->getMethod('getCacheKeyFromCertLocation');
        $cacheKeyMethod->setAccessible(true);
        $getCertsMethod = $reflector->getMethod('getCerts');
        $getCertsMethod->setAccessible(true);
        $cacheKey = $cacheKeyMethod->invoke($token, GoogleAuth::IAP_CERT_URL);
        $certs = $getCertsMethod->invoke(
            $token,
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

        $token = new GoogleAuth(
            null,
            $this->mockCache->reveal()
        );

        $token->mocks['decode'] = function ($token, $publicKey, $allowedAlgs) {
            $this->assertEquals(self::TEST_TOKEN, $token);
            $this->assertEquals(['RS256'], $allowedAlgs);

            return (object) [
                'iat' => time(),
                'exp' => time() + 30,
                'name' => 'foo',
                'iss' => AccessToken::OAUTH2_ISSUER_HTTPS
            ];;
        };

        $token->verify(self::TEST_TOKEN, [
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

        $token = new GoogleAuth(
            null,
            $this->mockCache->reveal()
        );

        $token->verify(self::TEST_TOKEN, [
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

        $token = new GoogleAuth(
            null,
            $this->mockCache->reveal()
        );

        $token->verify(self::TEST_TOKEN);
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

        $token = new GoogleAuth(
            null,
            $this->mockCache->reveal()
        );

        $token->verify(self::TEST_TOKEN, [
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

        $token = new GoogleAuth(
            $httpHandler,
            $this->mockCache->reveal()
        );

        $token->mocks['decode'] = function ($token, $publicKey, $allowedAlgs) {
            $this->assertEquals(self::TEST_TOKEN, $token);
            $this->assertEquals(['RS256'], $allowedAlgs);

            return (object) [
                'iat' => time(),
                'exp' => time() + 30,
                'name' => 'foo',
                'iss' => AccessToken::OAUTH2_ISSUER_HTTPS
            ];;
        };

        $token->verify(self::TEST_TOKEN);
    }

    public function testRetrieveCertsFromLocationRemoteBadRequest()
    {
        $this->expectException('RuntimeException');
        $this->expectExceptionMessage('bad news guys');

        $badBody = 'bad news guys';

        $httpClient = createHttpClient(function ($request) use ($badBody) {
            return new Response(500, [], $badBody);
        });

        $item = $this->prophesize('Psr\Cache\CacheItemInterface');
        $item->get()
            ->shouldBeCalledTimes(1)
            ->willReturn(null);

        $this->mockCache->getItem('google_auth_certs_cache|federated_signon_certs_v3')
            ->shouldBeCalledTimes(1)
            ->willReturn($item->reveal());

        $token = new GoogleAuth([
            'httpClient' => $httpClient,
            'cache' => $this->mockCache->reveal()
        ]);

        $token->verify(self::TEST_TOKEN);
    }

    /**
     * @dataProvider provideRevoke
     */
    public function testRevoke($input, $expected)
    {
        $httpHandler = function (RequestInterface $request) use ($expected) {
            $this->assertEquals('no-store', $request->getHeaderLine('Cache-Control'));
            $this->assertEquals('application/x-www-form-urlencoded', $request->getHeaderLine('Content-Type'));
            $this->assertEquals('POST', $request->getMethod());
            $this->assertEquals(GoogleAuth::OAUTH2_REVOKE_URI, (string) $request->getUri());
            $this->assertEquals('token=' . $expected, (string) $request->getBody());

            return new Response(200);
        };

        $token = new GoogleAuth($httpHandler);

        $this->assertTrue($token->revoke($input));
    }

    public function provideRevoke()
    {
        return [
            [
                self::TEST_TOKEN,
                self::TEST_TOKEN
            ], [
                ['refresh_token' => self::TEST_TOKEN, 'access_token' => 'other thing'],
                self::TEST_TOKEN
            ], [
                ['access_token' => self::TEST_TOKEN],
                self::TEST_TOKEN
            ]
        ];
    }

    public function testRevokeFails()
    {
        $httpHandler = function (RequestInterface $request) {
            return new Response(500);
        };

        $token = new GoogleAuth($httpHandler);

        $this->assertFalse($token->revoke(self::TEST_TOKEN));
    }
}
