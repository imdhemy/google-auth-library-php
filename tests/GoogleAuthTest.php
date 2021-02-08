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

class GoogleAuthTest extends BaseTest
{
    private $mockCacheItem;
    private $mockCache;
    private $targetAudience = 'a target audience';

    protected function setUp(): void
    {
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
     * @runInSeparateProcess
     */
    public function testIsFailsEnvSpecifiesNonExistentFile()
    {
        putenv('HOME');
        $keyFile = __DIR__ . '/fixtures' . '/does-not-exist-private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);
        GoogleAuth::getCredentials('a scope');
    }

    /**
     * @runInSeparateProcess
     */
    public function testLoadsOKIfEnvSpecifiedIsValid()
    {
        putenv('HOME');
        $keyFile = __DIR__ . '/fixtures' . '/private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);
        $this->assertNotNull(
            GoogleAuth::getCredentials('a scope')
        );
    }

    /**
     * @runInSeparateProcess
     */
    public function testLoadsDefaultFileIfPresentAndEnvVarIsNotSet()
    {
        putenv('HOME=' . __DIR__ . '/fixtures');
        putenv(ServiceAccountCredentials::ENV_VAR);
        $this->assertNotNull(
            GoogleAuth::getCredentials('a scope')
        );
    }

    /**
     * @expectedException DomainException
     * @runInSeparateProcess
     */
    public function testFailsIfNotOnGceAndNoDefaultFileFound()
    {
        putenv('HOME=' . __DIR__ . '/not_exist_fixtures');
        putenv(ServiceAccountCredentials::ENV_VAR);
        // simulate not being GCE and retry attempts by returning multiple 500s
        $httpHandler = getHandler([
            buildResponse(500),
            buildResponse(500),
            buildResponse(500)
        ]);

        GoogleAuth::getCredentials('a scope', $httpHandler);
    }

    /**
     * @runInSeparateProcess
     */
    public function testSuccedsIfNoDefaultFilesButIsOnCompute()
    {
        putenv('HOME');
        putenv(ServiceAccountCredentials::ENV_VAR);

        $wantedTokens = [
            'access_token' => '1/abdef1234567890',
            'expires_in' => '57',
            'token_type' => 'Bearer',
        ];
        $jsonTokens = json_encode($wantedTokens);

        // simulate the response from GCE.
        $httpHandler = getHandler([
            buildResponse(200, [ComputeCredentials::FLAVOR_HEADER => 'Google']),
            buildResponse(200, [], Psr7\stream_for($jsonTokens)),
        ]);

        $this->assertNotNull(
            GoogleAuth::getCredentials('a scope', $httpHandler)
        );
    }
}

class ADCDefaultScopeTest extends TestCase
{
    /** @runInSeparateProcess */
    public function testGceCredentials()
    {
        putenv('HOME');

        $jsonTokens = json_encode(['access_token' => 'abc']);

        $creds = ApplicationDefaultCredentials::getCredentials(
            null, // $scope
            $httpHandler = getHandler([
                buildResponse(200, [GCECredentials::FLAVOR_HEADER => 'Google']),
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

    /** @runInSeparateProcess */
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

    /** @runInSeparateProcess */
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

    /** @runInSeparateProcess */
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
}

class ADCGetMiddlewareTest extends TestCase
{
    private $originalHome;

    protected function setUp(): void
    {
        $this->originalHome = getenv('HOME');
    }

    protected function tearDown(): void
    {
        if ($this->originalHome != getenv('HOME')) {
            putenv('HOME=' . $this->originalHome);
        }
        putenv(ServiceAccountCredentials::ENV_VAR);  // removes it if assigned
    }

    /**
     * @expectedException DomainException
     */
    public function testIsFailsEnvSpecifiesNonExistentFile()
    {
        $keyFile = __DIR__ . '/fixtures' . '/does-not-exist-private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);
        GoogleAuth::getMiddleware('a scope');
    }

    public function testLoadsOKIfEnvSpecifiedIsValid()
    {
        $keyFile = __DIR__ . '/fixtures' . '/private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);
        $this->assertNotNull(GoogleAuth::getMiddleware('a scope'));
    }

    public function testLoadsDefaultFileIfPresentAndEnvVarIsNotSet()
    {
        putenv('HOME=' . __DIR__ . '/fixtures');
        $this->assertNotNull(GoogleAuth::getMiddleware('a scope'));
    }

    /**
     * @expectedException DomainException
     */
    public function testFailsIfNotOnComputeAndNoDefaultFileFound()
    {
        putenv('HOME=' . __DIR__ . '/not_exist_fixtures');

        // simulate not being GCE and retry attempts by returning multiple 500s
        $httpHandler = getHandler([
            buildResponse(500),
            buildResponse(500),
            buildResponse(500)
        ]);

        GoogleAuth::getMiddleware('a scope', $httpHandler);
    }

    public function testWithCacheOptions()
    {
        $keyFile = __DIR__ . '/fixtures' . '/private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);

        $httpHandler = getHandler([
            buildResponse(200),
        ]);

        $cacheOptions = [];
        $cachePool = $this->prophesize('Psr\Cache\CacheItemPoolInterface');

        $middleware = GoogleAuth::getMiddleware(
            'a scope',
            $httpHandler,
            $cacheOptions,
            $cachePool->reveal()
        );
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
        $httpHandler = getHandler([
            buildResponse(200, [ComputeCredentials::FLAVOR_HEADER => 'Google']),
            buildResponse(200, [], Psr7\stream_for($jsonTokens)),
        ]);

        $googleAuth = new GoogleAuth(['httpHandler' => $httpHandler]);
        $client = $googleAuth->makeHttpClient('a scope');

        $this->assertNotNull($client);
    }

    /**
     * @expectedException DomainException
     */
    public function testOnComputeCacheWithHit()
    {
        putenv('HOME=' . __DIR__ . '/not_exist_fixtures');

        $mockCacheItem = $this->prophesize('Psr\Cache\CacheItemInterface');
        $mockCacheItem->isHit()
            ->willReturn(true);
        $mockCacheItem->get()
            ->shouldBeCalledTimes(1)
            ->willReturn(false);

        $mockCache = $this->prophesize('Psr\Cache\CacheItemPoolInterface');
        $mockCache->getItem('google_auth_on_gce_cache')
            ->shouldBeCalledTimes(1)
            ->willReturn($mockCacheItem->reveal());

        ApplicationDefaultCredentials::getMiddleware(
            'a scope',
            null,
            null,
            $mockCache->reveal()
        );
    }

    public function testOnComputeCacheWithoutHit()
    {
        putenv('HOME=' . __DIR__ . '/not_exist_fixtures');

        $gceIsCalled = false;
        $dummyHandler = function ($request) use (&$gceIsCalled) {
            $gceIsCalled = true;
            return new Psr7\Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']);
        };
        $mockCacheItem = $this->prophesize('Psr\Cache\CacheItemInterface');
        $mockCacheItem->isHit()
            ->willReturn(false);
        $mockCacheItem->set(true)
            ->shouldBeCalledTimes(1);
        $mockCacheItem->expiresAfter(1500)
            ->shouldBeCalledTimes(1);

        $mockCache = $this->prophesize('Psr\Cache\CacheItemPoolInterface');
        $mockCache->getItem('google_auth_on_gce_cache')
            ->shouldBeCalledTimes(2)
            ->willReturn($mockCacheItem->reveal());
        $mockCache->save($mockCacheItem->reveal())
            ->shouldBeCalled();

        $creds = ApplicationDefaultCredentials::getMiddleware(
            'a scope',
            $dummyHandler,
            null,
            $mockCache->reveal()
        );

        $this->assertTrue($gceIsCalled);
    }

    public function testOnComputeCacheWithOptions()
    {
        putenv('HOME=' . __DIR__ . '/not_exist_fixtures');

        $prefix = 'test_prefix_';
        $lifetime = '70707';

        $gceIsCalled = false;
        $dummyHandler = function ($request) use (&$gceIsCalled) {
            $gceIsCalled = true;
            return new Psr7\Response(200, [GCECredentials::FLAVOR_HEADER => 'Google']);
        };
        $mockCacheItem = $this->prophesize('Psr\Cache\CacheItemInterface');
        $mockCacheItem->isHit()
            ->willReturn(false);
        $mockCacheItem->set(true)
            ->shouldBeCalledTimes(1);
        $mockCacheItem->expiresAfter($lifetime)
            ->shouldBeCalledTimes(1);

        $mockCache = $this->prophesize('Psr\Cache\CacheItemPoolInterface');
        $mockCache->getItem($prefix . 'google_auth_on_gce_cache')
            ->shouldBeCalledTimes(2)
            ->willReturn($mockCacheItem->reveal());
        $mockCache->save($mockCacheItem->reveal())
            ->shouldBeCalled();

        $creds = ApplicationDefaultCredentials::getMiddleware(
            'a scope',
            $dummyHandler,
            ['gce_prefix' => $prefix, 'gce_lifetime' => $lifetime],
            $mockCache->reveal()
        );

        $this->assertTrue($gceIsCalled);
    }

    /**
     * @expectedException DomainException
     * @runInSeparateProcess
     */
    public function testIsFailsEnvSpecifiesNonExistentFile()
    {
        putenv('HOME');
        $keyFile = __DIR__ . '/fixtures' . '/does-not-exist-private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);
        GoogleAuth::getIdTokenCredentials($this->targetAudience);
    }

    /**
     * @runInSeparateProcess
     */
    public function testLoadsOKIfEnvSpecifiedIsValid()
    {
        putenv('HOME');
        $keyFile = __DIR__ . '/fixtures' . '/private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);
        GoogleAuth::getIdTokenCredentials($this->targetAudience);
    }

    /**
     * @runInSeparateProcess
     */
    public function testLoadsDefaultFileIfPresentAndEnvVarIsNotSet()
    {
        putenv('HOME=' . __DIR__ . '/fixtures');
        putenv(ServiceAccountCredentials::ENV_VAR);
        GoogleAuth::getIdTokenCredentials($this->targetAudience);
    }

    /**
     * @expectedException DomainException
     */
    public function testFailsIfNotOnGceAndNoDefaultFileFound()
    {
        putenv('HOME=' . __DIR__ . '/not_exist_fixtures');
        putenv(ServiceAccountCredentials::ENV_VAR);

        // simulate not being GCE and retry attempts by returning multiple 500s
        $httpHandler = getHandler([
            buildResponse(500),
            buildResponse(500),
            buildResponse(500)
        ]);

        GoogleAuth::getIdTokenCredentials(
            $this->targetAudience,
            $httpHandler
        );
    }

    public function testWithCacheOptions()
    {
        putenv('HOME');
        $keyFile = __DIR__ . '/fixtures' . '/private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);

        $httpHandler = getHandler([
            buildResponse(200),
        ]);

        $cacheOptions = [];
        $cachePool = $this->prophesize('Psr\Cache\CacheItemPoolInterface');

        $credentials = GoogleAuth::getIdTokenCredentials(
            $this->targetAudience,
            $httpHandler,
            $cacheOptions,
            $cachePool->reveal()
        );

        $this->assertInstanceOf('Google\Auth\FetchAuthTokenCache', $credentials);
    }

    public function testIdTokenIfNoDefaultFilesButIsOnCompute()
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
            buildResponse(200, [ComputeCredentials::FLAVOR_HEADER => 'Google']),
            buildResponse(200, [], Psr7\stream_for($jsonTokens)),
        ]);

        $credentials = GoogleAuth::getIdTokenCredentials(
            $this->targetAudience,
            $httpHandler
        );

        $this->assertInstanceOf(
            'Google\Auth\Credentials\ComputeCredentials',
            $credentials
        );
    }
}

class ADCGetCredentialsWithQuotaProjectTest extends TestCase
{
    private $originalHome;
    private $quotaProject = 'a-quota-project';

    protected function setUp(): void
    {
        $this->originalHome = getenv('HOME');
    }

    protected function tearDown(): void
    {
        if ($this->originalHome != getenv('HOME')) {
            putenv('HOME=' . $this->originalHome);
        }
        putenv(ServiceAccountCredentials::ENV_VAR);  // removes environment variable
    }

    public function testWithServiceAccountCredentialsAndExplicitQuotaProject()
    {
        $keyFile = __DIR__ . '/fixtures' . '/private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);

        $credentials = GoogleAuth::getCredentials(
            null,
            null,
            null,
            null,
            $this->quotaProject
        );

        $this->assertInstanceOf(
            'Google\Auth\Credentials\ServiceAccountCredentials',
            $credentials
        );

        $this->assertEquals(
            $this->quotaProject,
            $credentials->getQuotaProject()
        );
    }

    public function testGetCredentialsUtilizesQuotaProjectInKeyFile()
    {
        $keyFile = __DIR__ . '/fixtures' . '/private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);

        $credentials = ApplicationDefaultCredentials::getCredentials();

        $this->assertEquals(
            'test_quota_project',
            $credentials->getQuotaProject()
        );
    }

    public function testWithFetchAuthTokenCacheAndExplicitQuotaProject()
    {
        $keyFile = __DIR__ . '/fixtures' . '/private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);

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
            $this->quotaProject
        );

        $this->assertInstanceOf('Google\Auth\FetchAuthTokenCache', $credentials);

        $this->assertEquals(
            $this->quotaProject,
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
            buildResponse(200, [ComputeCredentials::FLAVOR_HEADER => 'Google']),
            buildResponse(200, [], Psr7\stream_for($jsonTokens)),
        ]);

        $credentials = GoogleAuth::getCredentials(
            null,
            $httpHandler,
            null,
            null,
            $this->quotaProject
        );

        $this->assertInstanceOf(
            'Google\Auth\Credentials\ComputeCredentials',
            $credentials
        );

        $this->assertEquals(
            $this->quotaProject,
            $credentials->getQuotaProject()
        );
    }
}

class ADCGetCredentialsAppEngineTest extends BaseTest
{
    private $originalHome;
    private $originalServiceAccount;
    private $targetAudience = 'a target audience';

    protected function setUp(): void
    {
        // set home to be somewhere else
        $this->originalHome = getenv('HOME');
        putenv('HOME=' . __DIR__ . '/not_exist_fixtures');

        // remove service account path
        $this->originalServiceAccount = getenv(ServiceAccountCredentials::ENV_VAR);
        putenv(ServiceAccountCredentials::ENV_VAR);
    }

    protected function tearDown(): void
    {
        // removes it if assigned
        putenv('HOME=' . $this->originalHome);
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $this->originalServiceAccount);
        putenv('GAE_INSTANCE');
    }

    /**
     * @runInSeparateProcess
     */
    public function testAppEngineStandard()
    {
        $_SERVER['SERVER_SOFTWARE'] = 'Google App Engine';
        $this->assertInstanceOf(
            'Google\Auth\Credentials\AppIdentityCredentials',
            GoogleAuth::getCredentials()
        );
    }

    /**
     * @runInSeparateProcess
     */
    public function testAppEngineFlexible()
    {
        $_SERVER['SERVER_SOFTWARE'] = 'Google App Engine';
        putenv('GAE_INSTANCE=aef-default-20180313t154438');
        $httpHandler = getHandler([
            buildResponse(200, [ComputeCredentials::FLAVOR_HEADER => 'Google']),
        ]);
        $this->assertInstanceOf(
            'Google\Auth\Credentials\ComputeCredentials',
            GoogleAuth::getCredentials(null, $httpHandler)
        );
    }

    /**
     * @runInSeparateProcess
     */
    public function testAppEngineFlexibleIdToken()
    {
        $_SERVER['SERVER_SOFTWARE'] = 'Google App Engine';
        putenv('GAE_INSTANCE=aef-default-20180313t154438');
        $httpHandler = getHandler([
            buildResponse(200, [ComputeCredentials::FLAVOR_HEADER => 'Google']),
        ]);
        $creds = GoogleAuth::getIdTokenCredentials(
            $this->targetAudience,
            $httpHandler
        );
        $this->assertInstanceOf(
            'Google\Auth\Credentials\ComputeCredentials',
            $creds
        );
    }
}


/**
 * @group access-token
 */
class GoogleAuthFetchCertsTest extends TestCase
{
    private $cache;
    private $payload;

    private $token;
    private $publicKey;
    private $allowedAlgs;

    public function setUp(): void
    {
        $this->cache = $this->prophesize('Psr\Cache\CacheItemPoolInterface');
        $this->jwt = $this->prophesize('Firebase\JWT\JWT');
        $this->token = 'foobar';
        $this->publicKey = 'barfoo';

        $this->payload = [
            'iat' => time(),
            'exp' => time() + 30,
            'name' => 'foo',
            'iss' => AccessToken::OAUTH2_ISSUER_HTTPS
        ];
    }

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

        $this->cache->getItem('google_auth_certs_cache|' . sha1($certsLocation))
            ->shouldBeCalledTimes(1)
            ->willReturn($item->reveal());

        $this->cache->save(Argument::type('Psr\Cache\CacheItemInterface'))
            ->shouldBeCalledTimes(1);

        $token = new GoogleAuth(
            null,
            $this->cache->reveal()
        );

        $token->mocks['decode'] = function ($token, $publicKey, $allowedAlgs) {
            $this->assertEquals($this->token, $token);
            $this->assertEquals(['RS256'], $allowedAlgs);

            return (object) $this->payload;
        };

        $token->verify($this->token, [
            'certsLocation' => $certsLocation
        ]);
    }

    /**
     * @expectedException InvalidArgumentException
     * @expectedExceptionMessage Failed to retrieve verification certificates from path
     */
    public function testRetrieveCertsFromLocationLocalFileInvalidFilePath()
    {
        $certsLocation = __DIR__ . '/fixtures/federated-certs-does-not-exist.json';

        $item = $this->prophesize('Psr\Cache\CacheItemInterface');
        $item->get()
            ->shouldBeCalledTimes(1)
            ->willReturn(null);

        $this->cache->getItem('google_auth_certs_cache|' . sha1($certsLocation))
            ->shouldBeCalledTimes(1)
            ->willReturn($item->reveal());

        $token = new GoogleAuth(
            null,
            $this->cache->reveal()
        );

        $token->verify($this->token, [
            'certsLocation' => $certsLocation
        ]);
    }

    /**
     * @expectedException InvalidArgumentException
     * @expectedExceptionMessage federated sign-on certs expects "keys" to be set
     */
    public function testRetrieveCertsInvalidData()
    {
        $item = $this->prophesize('Psr\Cache\CacheItemInterface');
        $item->get()
            ->shouldBeCalledTimes(1)
            ->willReturn('{}');

        $this->cache->getItem('google_auth_certs_cache|federated_signon_certs_v3')
            ->shouldBeCalledTimes(1)
            ->willReturn($item->reveal());

        $token = new GoogleAuth(
            null,
            $this->cache->reveal()
        );

        $token->verify($this->token);
    }

    /**
     * @expectedException InvalidArgumentException
     * @expectedExceptionMessage federated sign-on certs expects "keys" to be set
     */
    public function testRetrieveCertsFromLocationLocalFileInvalidFileData()
    {
        $temp = tmpfile();
        fwrite($temp, '{}');
        $certsLocation = stream_get_meta_data($temp)['uri'];

        $item = $this->prophesize('Psr\Cache\CacheItemInterface');
        $item->get()
            ->shouldBeCalledTimes(1)
            ->willReturn(null);

        $this->cache->getItem('google_auth_certs_cache|' . sha1($certsLocation))
            ->shouldBeCalledTimes(1)
            ->willReturn($item->reveal());

        $token = new GoogleAuth(
            null,
            $this->cache->reveal()
        );

        $token->verify($this->token, [
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

        $this->cache->getItem('google_auth_certs_cache|federated_signon_certs_v3')
            ->shouldBeCalledTimes(1)
            ->willReturn($item->reveal());

        $this->cache->save(Argument::type('Psr\Cache\CacheItemInterface'))
            ->shouldBeCalledTimes(1);

        $token = new GoogleAuth(
            $httpHandler,
            $this->cache->reveal()
        );

        $token->mocks['decode'] = function ($token, $publicKey, $allowedAlgs) {
            $this->assertEquals($this->token, $token);
            $this->assertEquals(['RS256'], $allowedAlgs);

            return (object) $this->payload;
        };

        $token->verify($this->token);
    }

    /**
     * @expectedException RuntimeException
     * @expectedExceptionMessage bad news guys
     */
    public function testRetrieveCertsFromLocationRemoteBadRequest()
    {
        $badBody = 'bad news guys';

        $httpHandler = function (RequestInterface $request) use ($badBody) {
            return new Response(500, [], $badBody);
        };

        $item = $this->prophesize('Psr\Cache\CacheItemInterface');
        $item->get()
            ->shouldBeCalledTimes(1)
            ->willReturn(null);

        $this->cache->getItem('google_auth_certs_cache|federated_signon_certs_v3')
            ->shouldBeCalledTimes(1)
            ->willReturn($item->reveal());

        $token = new GoogleAuth(
            $httpHandler,
            $this->cache->reveal()
        );

        $token->verify($this->token);
    }

    /**
     * @dataProvider revokeTokens
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

    public function revokeTokens()
    {
        $this->setUp();

        return [
            [
                $this->token,
                $this->token
            ], [
                ['refresh_token' => $this->token, 'access_token' => 'other thing'],
                $this->token
            ], [
                ['access_token' => $this->token],
                $this->token
            ]
        ];
    }

    public function testRevokeFails()
    {
        $httpHandler = function (RequestInterface $request) {
            return new Response(500);
        };

        $token = new GoogleAuth($httpHandler);

        $this->assertFalse($token->revoke($this->token));
    }
}
