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

use Google\Auth\ApplicationDefaultCredentials;
use Google\Auth\Credentials\ServiceAccountCredentials;
use Google\Auth\Credentials\ServiceAccountJwtAccessCredentials;
use Google\Auth\CredentialsLoader;
use Google\Auth\OAuth2;
use GuzzleHttp\Psr7;
use PHPUnit\Framework\TestCase;

// Creates a standard JSON auth object for testing.
function createSACTestJson()
{
    return [
        'private_key_id' => 'key123',
        'private_key' => 'privatekey',
        'client_email' => 'test@example.com',
        'client_id' => 'client123',
        'type' => 'service_account',
        'project_id' => 'example_project'
    ];
}

class SACGetCacheKeyTest extends TestCase
{
    public function testShouldBeTheSameAsOAuth2WithTheSameScope()
    {
        $testJson = createSACTestJson();
        $scope = ['scope/1', 'scope/2'];
        $sa = new ServiceAccountCredentials(
            $scope,
            $testJson
        );
        $o = new OAuth2(['scope' => $scope]);
        $this->assertSame(
            $testJson['client_email'] . ':' . $o->getCacheKey(),
            $sa->getCacheKey()
        );
    }

    public function testShouldBeTheSameAsOAuth2WithTheSameScopeWithSub()
    {
        $testJson = createSACTestJson();
        $scope = ['scope/1', 'scope/2'];
        $sub = 'sub123';
        $sa = new ServiceAccountCredentials(
            $scope,
            $testJson,
            $sub
        );
        $o = new OAuth2(['scope' => $scope]);
        $this->assertSame(
            $testJson['client_email'] . ':' . $o->getCacheKey() . ':' . $sub,
            $sa->getCacheKey()
        );
    }

    public function testShouldBeTheSameAsOAuth2WithTheSameScopeWithSubAddedLater()
    {
        $testJson = createSACTestJson();
        $scope = ['scope/1', 'scope/2'];
        $sub = 'sub123';
        $sa = new ServiceAccountCredentials(
            $scope,
            $testJson,
            null
        );
        $sa->setSub($sub);

        $o = new OAuth2(['scope' => $scope]);
        $this->assertSame(
            $testJson['client_email'] . ':' . $o->getCacheKey() . ':' . $sub,
            $sa->getCacheKey()
        );
    }
}

class SACConstructorTest extends TestCase
{
    /**
     * @expectedException InvalidArgumentException
     */
    public function testShouldFailIfScopeIsNotAValidType()
    {
        $testJson = createSACTestJson();
        $notAnArrayOrString = new \stdClass();
        $sa = new ServiceAccountCredentials(
            $notAnArrayOrString,
            $testJson
        );
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testShouldFailIfJsonDoesNotHaveClientEmail()
    {
        $testJson = createSACTestJson();
        unset($testJson['client_email']);
        $scope = ['scope/1', 'scope/2'];
        $sa = new ServiceAccountCredentials(
            $scope,
            $testJson
        );
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testShouldFailIfJsonDoesNotHavePrivateKey()
    {
        $testJson = createSACTestJson();
        unset($testJson['private_key']);
        $scope = ['scope/1', 'scope/2'];
        $sa = new ServiceAccountCredentials(
            $scope,
            $testJson
        );
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testFailsToInitalizeFromANonExistentFile()
    {
        $keyFile = __DIR__ . '/../fixtures' . '/does-not-exist-private.json';
        new ServiceAccountCredentials('scope/1', $keyFile);
    }

    public function testInitalizeFromAFile()
    {
        $keyFile = __DIR__ . '/../fixtures' . '/private.json';
        $this->assertNotNull(
            new ServiceAccountCredentials('scope/1', $keyFile)
        );
    }

    /**
     * @expectedException LogicException
     */
    public function testFailsToInitializeFromInvalidJsonData()
    {
        $tmp = tmpfile();
        fwrite($tmp, '{');

        $path = stream_get_meta_data($tmp)['uri'];

        try {
            new ServiceAccountCredentials('scope/1', $path);
        } catch (\Exception $e) {
            fclose($tmp);
            throw $e;
        }
    }
}

class SACFromEnvTest extends TestCase
{
    protected function tearDown(): void
    {
        putenv(ServiceAccountCredentials::ENV_VAR);  // removes it from
    }

    public function testIsNullIfEnvVarIsNotSet()
    {
        $this->assertNull(ServiceAccountCredentials::fromEnv());
    }

    /**
     * @expectedException DomainException
     */
    public function testFailsIfEnvSpecifiesNonExistentFile()
    {
        $keyFile = __DIR__ . '/../fixtures' . '/does-not-exist-private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);
        ApplicationDefaultCredentials::getCredentials('a scope');
    }

    public function testSucceedIfFileExists()
    {
        $keyFile = __DIR__ . '/../fixtures' . '/private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);
        $this->assertNotNull(ApplicationDefaultCredentials::getCredentials('a scope'));
    }
}

class SACFromWellKnownFileTest extends TestCase
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
    }

    public function testIsNullIfFileDoesNotExist()
    {
        putenv('HOME=' . __DIR__ . '/../not_exists_fixtures');
        $this->assertNull(
            ServiceAccountCredentials::fromWellKnownFile()
        );
    }

    public function testSucceedIfFileIsPresent()
    {
        putenv('HOME=' . __DIR__ . '/../fixtures');
        $this->assertNotNull(
            ApplicationDefaultCredentials::getCredentials('a scope')
        );
    }
}

class SACFetchAuthTokenTest extends TestCase
{
    private $privateKey;

    public function setUp(): void
    {
        $this->privateKey =
            file_get_contents(__DIR__ . '/../fixtures' . '/private.pem');
    }

    private function createTestJson()
    {
        $testJson = createSACTestJson();
        $testJson['private_key'] = $this->privateKey;

        return $testJson;
    }

    /**
     * @expectedException GuzzleHttp\Exception\ClientException
     */
    public function testFailsOnClientErrors()
    {
        $testJson = $this->createTestJson();
        $scope = ['scope/1', 'scope/2'];
        $httpHandler = getHandler([
            buildResponse(400),
        ]);
        $sa = new ServiceAccountCredentials(
            $scope,
            $testJson
        );
        $sa->fetchAuthToken($httpHandler);
    }

    /**
     * @expectedException GuzzleHttp\Exception\ServerException
     */
    public function testFailsOnServerErrors()
    {
        $testJson = $this->createTestJson();
        $scope = ['scope/1', 'scope/2'];
        $httpHandler = getHandler([
            buildResponse(500),
        ]);
        $sa = new ServiceAccountCredentials(
            $scope,
            $testJson
        );
        $sa->fetchAuthToken($httpHandler);
    }

    public function testCanFetchCredsOK()
    {
        $testJson = $this->createTestJson();
        $testJsonText = json_encode($testJson);
        $scope = ['scope/1', 'scope/2'];
        $httpHandler = getHandler([
            buildResponse(200, [], Psr7\stream_for($testJsonText)),
        ]);
        $sa = new ServiceAccountCredentials(
            $scope,
            $testJson
        );
        $tokens = $sa->fetchAuthToken($httpHandler);
        $this->assertEquals($testJson, $tokens);
    }

    public function testUpdateMetadataFunc()
    {
        $testJson = $this->createTestJson();
        $scope = ['scope/1', 'scope/2'];
        $access_token = 'accessToken123';
        $responseText = json_encode(array('access_token' => $access_token));
        $httpHandler = getHandler([
            buildResponse(200, [], Psr7\stream_for($responseText)),
        ]);
        $sa = new ServiceAccountCredentials(
            $scope,
            $testJson
        );
        $update_metadata = $sa->getUpdateMetadataFunc();
        $this->assertInternalType('callable', $update_metadata);

        $actual_metadata = call_user_func(
            $update_metadata,
            $metadata = array('foo' => 'bar'),
            $authUri = null,
            $httpHandler
        );
        $this->assertArrayHasKey(
            CredentialsLoader::AUTH_METADATA_KEY,
            $actual_metadata
        );
        $this->assertEquals(
            $actual_metadata[CredentialsLoader::AUTH_METADATA_KEY],
            array('Bearer ' . $access_token)
        );
    }

    public function testShouldBeIdTokenWhenTargetAudienceIsSet()
    {
        $testJson = $this->createTestJson();
        $expectedToken = ['id_token' => 'idtoken12345'];
        $timesCalled = 0;
        $httpHandler = function ($request) use (&$timesCalled, $expectedToken) {
            $timesCalled++;
            parse_str($request->getBody(), $post);
            $this->assertArrayHasKey('assertion', $post);
            list($header, $payload, $sig) = explode('.', $post['assertion']);
            $jwtParams = json_decode(base64_decode($payload), true);
            $this->assertArrayHasKey('target_audience', $jwtParams);
            $this->assertEquals('a target audience', $jwtParams['target_audience']);

            return new Psr7\Response(200, [], Psr7\stream_for(json_encode($expectedToken)));
        };
        $sa = new ServiceAccountCredentials(null, $testJson, null, 'a target audience');
        $this->assertEquals($expectedToken, $sa->fetchAuthToken($httpHandler));
        $this->assertEquals(1, $timesCalled);
    }

    /**
     * @expectedException InvalidArgumentException
     * @expectedExceptionMessage Scope and targetAudience cannot both be supplied
     */
    public function testSettingBothScopeAndTargetAudienceThrowsException()
    {
        $testJson = $this->createTestJson();
        $sa = new ServiceAccountCredentials(
            'a-scope',
            $testJson,
            null,
            'a-target-audience'
        );
    }
}

class SACGetClientNameTest extends TestCase
{
    public function testReturnsClientEmail()
    {
        $testJson = createSACTestJson();
        $sa = new ServiceAccountCredentials('scope/1', $testJson);
        $this->assertEquals($testJson['client_email'], $sa->getClientEmail());
    }
}

class SACGetProjectIdTest extends TestCase
{
    public function testGetProjectId()
    {
        $testJson = createSACTestJson();
        $sa = new ServiceAccountCredentials('scope/1', $testJson);
        $this->assertEquals($testJson['project_id'], $sa->getProjectId());
    }
}

class SACGetQuotaProjectTest extends TestCase
{
    public function testGetQuotaProject()
    {
        $keyFile = __DIR__ . '/../fixtures' . '/private.json';
        $sa = new ServiceAccountCredentials('scope/1', $keyFile);
        $this->assertEquals('test_quota_project', $sa->getQuotaProject());
    }
}
