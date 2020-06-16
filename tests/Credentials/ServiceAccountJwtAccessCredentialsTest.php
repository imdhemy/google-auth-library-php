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
use Google\Auth\Credentials\ServiceAccountJwtAccessCredentials;
use Google\Auth\CredentialsLoader;
use Google\Auth\OAuth2;
use GuzzleHttp\Psr7;
use PHPUnit\Framework\TestCase;

// Creates a standard JSON auth object for testing.
function createTestJson()
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

class SACJwtAccessTest extends TestCase
{
    private $privateKey;

    public function setUp()
    {
        $this->privateKey =
            file_get_contents(__DIR__ . '/../fixtures' . '/private.pem');
    }

    private function createTestJson()
    {
        $testJson = createTestJson();
        $testJson['private_key'] = $this->privateKey;

        return $testJson;
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testFailsToInitalizeFromANonExistentFile()
    {
        $keyFile = __DIR__ . '/../fixtures' . '/does-not-exist-private.json';
        new ServiceAccountJwtAccessCredentials($keyFile);
    }

    public function testInitalizeFromAFile()
    {
        $keyFile = __DIR__ . '/../fixtures' . '/private.json';
        $this->assertNotNull(
            new ServiceAccountJwtAccessCredentials($keyFile)
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
            new ServiceAccountJwtAccessCredentials($path);
        } catch (\Exception $e) {
            fclose($tmp);
            throw $e;
        }
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testFailsOnMissingClientEmail()
    {
        $testJson = $this->createTestJson();
        unset($testJson['client_email']);
        $sa = new ServiceAccountJwtAccessCredentials(
            $testJson
        );
    }

    /**
     * @expectedException InvalidArgumentException
     */
    public function testFailsOnMissingPrivateKey()
    {
        $testJson = $this->createTestJson();
        unset($testJson['private_key']);
        $sa = new ServiceAccountJwtAccessCredentials(
            $testJson
        );
    }

    public function testCanInitializeFromJson()
    {
        $testJson = $this->createTestJson();
        $sa = new ServiceAccountJwtAccessCredentials(
            $testJson
        );
        $this->assertNotNull($sa);
    }

    public function testNoOpOnFetchAuthToken()
    {
        $testJson = $this->createTestJson();
        $sa = new ServiceAccountJwtAccessCredentials(
            $testJson
        );
        $this->assertNotNull($sa);

        $httpHandler = getHandler([
            buildResponse(200),
        ]);
        $result = $sa->fetchAuthToken($httpHandler); // authUri has not been set
        $this->assertNull($result);
    }

    public function testAuthUriIsNotSet()
    {
        $testJson = $this->createTestJson();
        $sa = new ServiceAccountJwtAccessCredentials(
            $testJson
        );
        $this->assertNotNull($sa);

        $update_metadata = $sa->getUpdateMetadataFunc();
        $this->assertInternalType('callable', $update_metadata);

        $actual_metadata = call_user_func(
            $update_metadata,
            $metadata = array('foo' => 'bar'),
            $authUri = null
        );
        $this->assertArrayNotHasKey(
            CredentialsLoader::AUTH_METADATA_KEY,
            $actual_metadata
        );
    }

    public function testUpdateMetadataFunc()
    {
        $testJson = $this->createTestJson();
        $sa = new ServiceAccountJwtAccessCredentials(
            $testJson
        );
        $this->assertNotNull($sa);

        $update_metadata = $sa->getUpdateMetadataFunc();
        $this->assertInternalType('callable', $update_metadata);

        $actual_metadata = call_user_func(
            $update_metadata,
            $metadata = array('foo' => 'bar'),
            $authUri = 'https://example.com/service'
        );
        $this->assertArrayHasKey(
            CredentialsLoader::AUTH_METADATA_KEY,
            $actual_metadata
        );

        $authorization = $actual_metadata[CredentialsLoader::AUTH_METADATA_KEY];
        $this->assertInternalType('array', $authorization);

        $bearer_token = current($authorization);
        $this->assertInternalType('string', $bearer_token);
        $this->assertEquals(0, strpos($bearer_token, 'Bearer '));
        $this->assertGreaterThan(30, strlen($bearer_token));

        $actual_metadata2 = call_user_func(
            $update_metadata,
            $metadata = array('foo' => 'bar'),
            $authUri = 'https://example.com/anotherService'
        );
        $this->assertArrayHasKey(
            CredentialsLoader::AUTH_METADATA_KEY,
            $actual_metadata2
        );

        $authorization2 = $actual_metadata2[CredentialsLoader::AUTH_METADATA_KEY];
        $this->assertInternalType('array', $authorization2);

        $bearer_token2 = current($authorization2);
        $this->assertInternalType('string', $bearer_token2);
        $this->assertEquals(0, strpos($bearer_token2, 'Bearer '));
        $this->assertGreaterThan(30, strlen($bearer_token2));
        $this->assertNotEquals($bearer_token2, $bearer_token);
    }
}

class SACJwtAccessComboTest extends TestCase
{
    private $privateKey;

    public function setUp()
    {
        $this->privateKey =
            file_get_contents(__DIR__ . '/../fixtures' . '/private.pem');
    }

    private function createTestJson()
    {
        $testJson = createTestJson();
        $testJson['private_key'] = $this->privateKey;

        return $testJson;
    }

    public function testNoScopeUseJwtAccess()
    {
        $testJson = $this->createTestJson();
        // no scope, jwt access should be used, no outbound
        // call should be made
        $scope = null;
        $sa = new ServiceAccountCredentials(
            $scope,
            $testJson
        );
        $this->assertNotNull($sa);

        $update_metadata = $sa->getUpdateMetadataFunc();
        $this->assertInternalType('callable', $update_metadata);

        $actual_metadata = call_user_func(
            $update_metadata,
            $metadata = array('foo' => 'bar'),
            $authUri = 'https://example.com/service'
        );
        $this->assertArrayHasKey(
            CredentialsLoader::AUTH_METADATA_KEY,
            $actual_metadata
        );

        $authorization = $actual_metadata[CredentialsLoader::AUTH_METADATA_KEY];
        $this->assertInternalType('array', $authorization);

        $bearer_token = current($authorization);
        $this->assertInternalType('string', $bearer_token);
        $this->assertEquals(0, strpos($bearer_token, 'Bearer '));
        $this->assertGreaterThan(30, strlen($bearer_token));
    }

    public function testNoScopeAndNoAuthUri()
    {
        $testJson = $this->createTestJson();
        // no scope, jwt access should be used, no outbound
        // call should be made
        $scope = null;
        $sa = new ServiceAccountCredentials(
            $scope,
            $testJson
        );
        $this->assertNotNull($sa);

        $update_metadata = $sa->getUpdateMetadataFunc();
        $this->assertInternalType('callable', $update_metadata);

        $actual_metadata = call_user_func(
            $update_metadata,
            $metadata = array('foo' => 'bar'),
            $authUri = null
        );
        // no access_token is added to the metadata hash
        // but also, no error should be thrown
        $this->assertInternalType('array', $actual_metadata);
        $this->assertArrayNotHasKey(
            CredentialsLoader::AUTH_METADATA_KEY,
            $actual_metadata
        );
    }
}

class SACJWTGetCacheKeyTest extends TestCase
{
    public function testShouldBeTheSameAsOAuth2WithTheSameScope()
    {
        $testJson = createTestJson();
        $scope = ['scope/1', 'scope/2'];
        $sa = new ServiceAccountJwtAccessCredentials($testJson);
        $this->assertNull($sa->getCacheKey());
    }
}

class SACJWTGetClientNameTest extends TestCase
{
    public function testReturnsClientEmail()
    {
        $testJson = createTestJson();
        $sa = new ServiceAccountJwtAccessCredentials($testJson);
        $this->assertEquals($testJson['client_email'], $sa->getClientEmail());
    }
}

class SACJWTGetProjectIdTest extends TestCase
{
    public function testGetProjectId()
    {
        $testJson = createTestJson();
        $sa = new ServiceAccountJwtAccessCredentials($testJson);
        $this->assertEquals($testJson['project_id'], $sa->getProjectId());
    }
}
