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
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use InvalidArgumentException;
use LogicException;

class ServiceAccountJwtAccessCredentialsTest extends TestCase
{
    private const AUDIENCE = 'http://aud/';

    private $testJson = [
        'private_key_id' => 'key123',
        'private_key' => 'privatekey',
        'client_email' => 'test@example.com',
        'client_id' => 'client123',
        'type' => 'service_account',
        'project_id' => 'example_project'
    ];

    private static $privateKey;

    public static function setUpBeforeClass(): void
    {
        self::$privateKey = file_get_contents(
            __DIR__ . '/../fixtures/private.pem'
        );
    }

    public function testFailsToInitalizeFromANonExistentFile()
    {
        $this->expectException(InvalidArgumentException::class);
        $keyFile = __DIR__ . '/does-not-exist-private.json';
        new ServiceAccountJwtAccessCredentials($keyFile, self::AUDIENCE);
    }

    public function testInitalizeFromAFile()
    {
        $keyFile = __DIR__ . '/../fixtures/private.json';
        $this->assertNotNull(
            new ServiceAccountJwtAccessCredentials($keyFile, self::AUDIENCE)
        );
    }

    public function testFailsToInitializeFromInvalidJsonData()
    {
        $this->expectException(LogicException::class);
        $tmp = tmpfile();
        fwrite($tmp, '{');

        $path = stream_get_meta_data($tmp)['uri'];

        try {
            new ServiceAccountJwtAccessCredentials($path, self::AUDIENCE);
        } finally {
            fclose($tmp);
        }
    }

    public function testFailsOnMissingClientEmail()
    {
        $this->expectException(InvalidArgumentException::class);
        unset($this->testJson['client_email']);
        $credentials = new ServiceAccountJwtAccessCredentials(
            $this->testJson,
            self::AUDIENCE
        );
    }

    public function testFailsOnMissingPrivateKey()
    {
        $this->expectException(InvalidArgumentException::class);
        unset($this->testJson['private_key']);
        $credentials = new ServiceAccountJwtAccessCredentials(
            $this->testJson,
            self::AUDIENCE
        );
    }

    public function testCanInitializeFromJson()
    {
        $credentials = new ServiceAccountJwtAccessCredentials(
            $this->testJson,
            self::AUDIENCE
        );
        $this->assertNotNull($credentials);
    }

    public function testGetRequestMetadata()
    {
        $this->testJson['private_key'] = self::$privateKey;

        $credentials = new ServiceAccountJwtAccessCredentials(
            $this->testJson,
            self::AUDIENCE
        );

        $metadata = $credentials->getRequestMetadata();

        $this->assertArrayHasKey('Authorization', $metadata);

        $bearer_token = $metadata['Authorization'];

        $this->assertIsString($bearer_token);
        $this->assertEquals(0, strpos($bearer_token, 'Bearer '));
        $this->assertGreaterThan(30, strlen($bearer_token));

        $credentials2 = new ServiceAccountJwtAccessCredentials(
            $this->testJson,
            'https://example.com/anotherService'
        );

        $metadata2 = $credentials2->getRequestMetadata();

        $this->assertArrayHasKey('Authorization', $metadata2);

        $bearer_token2 = $metadata2['Authorization'];

        $this->assertIsString($bearer_token2);
        $this->assertEquals(0, strpos($bearer_token2, 'Bearer '));
        $this->assertGreaterThan(30, strlen($bearer_token2));
        $this->assertNotEquals($bearer_token2, $bearer_token);
    }

    public function testCacheKeyShouldBeTheAudience()
    {
        $this->testJson['private_key'] = self::$privateKey;
        $credentials = new ServiceAccountJwtAccessCredentials(
            $this->testJson,
            self::AUDIENCE
        );

        $reflection = new \ReflectionClass($credentials);
        $method = $reflection->getMethod('getCacheKey');
        $method->setAccessible(true);
        $cacheKey = $method->invoke($credentials);

        $this->assertEquals(self::AUDIENCE, $cacheKey);
    }

    public function testReturnsClientEmail()
    {
        $this->testJson['private_key'] = self::$privateKey;
        $credentials = new ServiceAccountJwtAccessCredentials(
            $this->testJson,
            self::AUDIENCE
        );
        $this->assertEquals(
            $this->testJson['client_email'],
            $credentials->getClientEmail()
        );
    }

    public function testGetProjectId()
    {
        $this->testJson['private_key'] = self::$privateKey;
        $credentials = new ServiceAccountJwtAccessCredentials(
            $this->testJson,
            self::AUDIENCE
        );
        $this->assertEquals(
            $this->testJson['project_id'],
            $credentials->getProjectId()
        );
    }

    public function testGetQuotaProject()
    {
        $keyFile = __DIR__ . '/../fixtures/private.json';
        $credentials = new ServiceAccountJwtAccessCredentials(
            $keyFile,
            self::AUDIENCE
        );
        $this->assertEquals(
            'test_quota_project',
            $credentials->getQuotaProject()
        );
    }
}
