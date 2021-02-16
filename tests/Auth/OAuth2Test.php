<?php
/*
 * Copyright 2010 Google Inc.
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
use Google\Auth\OAuth2;
use GuzzleHttp\Psr7;
use PHPUnit\Framework\TestCase;

class OAuth2Test extends TestCase
{
    private $privateKey;
    private $cache;
    private $payload;
    private $publicKey;
    private $allowedAlgs;

    private $justClientId = [
        'clientID' => 'aClientID',
    ];

    private $minimal = [
        'authorizationUri' => 'https://accounts.test.org/insecure/url',
        'redirectUri' => 'https://accounts.test.org/redirect/url',
        'clientId' => 'aClientID',
    ];

    private $verifyIdTokenMinimal = [
        'scope' => 'https://www.googleapis.com/auth/userinfo.profile',
        'audience' => 'myaccount.on.host.issuer.com',
        'issuer' => 'an.issuer.com',
        'clientId' => 'myaccount.on.host.issuer.com',
    ];

    private $fetchAuthTokenMinimal = [
        'tokenCredentialUri' => 'https://tokens_r_us/test',
        'scope' => 'https://www.googleapis.com/auth/userinfo.profile',
        'signingKey' => 'example_key',
        'signingAlgorithm' => 'HS256',
        'issuer' => 'app@example.com',
        'audience' => 'accounts.google.com',
        'clientId' => 'aClientID',
    ];

    private $tokenRequestMinimal = [
        'tokenCredentialUri' => 'https://tokens_r_us/test',
        'scope' => 'https://www.googleapis.com/auth/userinfo.profile',
        'issuer' => 'app@example.com',
        'audience' => 'accounts.google.com',
        'clientId' => 'aClientID',
    ];

    private $signingMinimal = [
        'signingKey' => 'example_key',
        'signingAlgorithm' => 'HS256',
        'scope' => 'https://www.googleapis.com/auth/userinfo.profile',
        'issuer' => 'app@example.com',
        'audience' => 'accounts.google.com',
        'clientId' => 'aClientID',
    ];

    public function setUp(): void
    {
        $this->publicKey =
            file_get_contents(__DIR__ . '/fixtures/public.pem');
        $this->privateKey =
            file_get_contents(__DIR__ . '/fixtures/private.pem');
    }

    public function testIsNullIfAuthorizationUriIsNull()
    {
        $this->expectException('InvalidArgumentException');
        $o = new OAuth2();
        $this->assertNull($o->buildFullAuthorizationUri());
    }

    public function testRequiresTheClientId()
    {
        $this->expectException('InvalidArgumentException');
        $o = new OAuth2([
            'authorizationUri' => 'https://accounts.test.org/auth/url',
            'redirectUri' => 'https://accounts.test.org/redirect/url',
        ]);
        $o->buildFullAuthorizationUri();
    }

    public function testRequiresTheRedirectUri()
    {
        $this->expectException('InvalidArgumentException');
        $o = new OAuth2([
            'authorizationUri' => 'https://accounts.test.org/auth/url',
            'clientId' => 'aClientID',
        ]);
        $o->buildFullAuthorizationUri();
    }

    public function testCannotHavePromptAndApprovalPrompt()
    {
        $this->expectException('InvalidArgumentException');
        $o = new OAuth2([
            'authorizationUri' => 'https://accounts.test.org/auth/url',
            'clientId' => 'aClientID',
        ]);
        $o->buildFullAuthorizationUri([
            'approval_prompt' => 'an approval prompt',
            'prompt' => 'a prompt',
        ]);
    }

    public function testCannotHaveInsecureAuthorizationUri()
    {
        $this->expectException('InvalidArgumentException');
        $o = new OAuth2([
            'authorizationUri' => 'http://accounts.test.org/insecure/url',
            'redirectUri' => 'https://accounts.test.org/redirect/url',
            'clientId' => 'aClientID',
        ]);
        $o->buildFullAuthorizationUri();
    }

    public function testCannotHaveRelativeRedirectUri()
    {
        $this->expectException('InvalidArgumentException');
        $o = new OAuth2([
            'authorizationUri' => 'http://accounts.test.org/insecure/url',
            'redirectUri' => '/redirect/url',
            'clientId' => 'aClientID',
        ]);
        $o->buildFullAuthorizationUri();
    }

    public function testHasDefaultXXXTypeParams()
    {
        $o = new OAuth2($this->minimal);
        $q = Psr7\parse_query($o->buildFullAuthorizationUri()->getQuery());
        $this->assertEquals('code', $q['response_type']);
        $this->assertEquals('offline', $q['access_type']);
    }

    public function testCanOverrideParams()
    {
        $overrides = [
            'access_type' => 'o_access_type',
            'client_id' => 'o_client_id',
            'redirect_uri' => 'o_redirect_uri',
            'response_type' => 'o_response_type',
            'state' => 'o_state',
        ];
        $config = array_merge($this->minimal, ['state' => 'the_state']);
        $o = new OAuth2($config);
        $q = Psr7\parse_query($o->buildFullAuthorizationUri($overrides)->getQuery());
        $this->assertEquals('o_access_type', $q['access_type']);
        $this->assertEquals('o_client_id', $q['client_id']);
        $this->assertEquals('o_redirect_uri', $q['redirect_uri']);
        $this->assertEquals('o_response_type', $q['response_type']);
        $this->assertEquals('o_state', $q['state']);
    }

    public function testIncludesTheScope()
    {
        $with_strings = array_merge($this->minimal, ['scope' => 'scope1 scope2']);
        $o = new OAuth2($with_strings);
        $q = Psr7\parse_query($o->buildFullAuthorizationUri()->getQuery());
        $this->assertEquals('scope1 scope2', $q['scope']);

        $with_array = array_merge($this->minimal, [
            'scope' => ['scope1', 'scope2'],
        ]);
        $o = new OAuth2($with_array);
        $q = Psr7\parse_query($o->buildFullAuthorizationUri()->getQuery());
        $this->assertEquals('scope1 scope2', $q['scope']);
    }

    public function testRedirectUriPostmessageIsAllowed()
    {
        $o = new OAuth2([
            'authorizationUri' => 'https://accounts.test.org/insecure/url',
            'redirectUri' => 'postmessage',
            'clientId' => 'aClientID',
        ]);
        $this->assertEquals('postmessage', $o->getRedirectUri());
        $url = $o->buildFullAuthorizationUri();
        $parts = parse_url((string)$url);
        parse_str($parts['query'], $query);
        $this->assertArrayHasKey('redirect_uri', $query);
        $this->assertEquals('postmessage', $query['redirect_uri']);
    }

    public function testReturnsNullIfCannotBeInferred()
    {
        $o = new OAuth2($this->minimal);
        $this->assertNull($o->getGrantType());
    }

    public function testInfersAuthorizationCode()
    {
        $o = new OAuth2($this->minimal);
        $o->setCode('an auth code');
        $this->assertEquals('authorization_code', $o->getGrantType());
    }

    public function testInfersRefreshToken()
    {
        $o = new OAuth2($this->minimal);
        $o->setRefreshToken('a refresh token');
        $this->assertEquals('refresh_token', $o->getGrantType());
    }

    public function testInfersPassword()
    {
        $o = new OAuth2($this->minimal);
        $o->setPassword('a password');
        $o->setUsername('a username');
        $this->assertEquals('password', $o->getGrantType());
    }

    public function testInfersJwtBearer()
    {
        $o = new OAuth2($this->minimal);
        $o->setIssuer('an issuer');
        $o->setSigningKey('a key');
        $this->assertEquals(
            'urn:ietf:params:oauth:grant-type:jwt-bearer',
            $o->getGrantType()
        );
    }

    public function testSetsKnownTypes()
    {
        $o = new OAuth2($this->minimal);
        foreach (OAuth2::$knownGrantTypes as $t) {
            $o->setGrantType($t);
            $this->assertEquals($t, $o->getGrantType());
        }
    }

    public function testSetsUrlAsGrantType()
    {
        $o = new OAuth2($this->minimal);
        $o->setGrantType('http://a/grant/url');
        $this->assertEquals('http://a/grant/url', $o->getGrantType());
    }

    public function testIsNullWithNoScopesOrAudience()
    {
        $o = new OAuth2($this->justClientId);
        $this->assertNull($o->getCacheKey());
    }

    public function testIsScopeIfSingleScope()
    {
        $o = new OAuth2($this->justClientId);
        $o->setScope('test/scope/1');
        $this->assertEquals('test/scope/1', $o->getCacheKey());
    }

    public function testIsAllScopesWhenScopeIsArray()
    {
        $o = new OAuth2($this->justClientId);
        $o->setScope(['test/scope/1', 'test/scope/2']);
        $this->assertEquals('test/scope/1:test/scope/2', $o->getCacheKey());
    }

    public function testIsAudienceWhenScopeIsNull()
    {
        $aud = 'https://drive.googleapis.com';
        $o = new OAuth2($this->justClientId);
        $o->setAudience($aud);
        $this->assertEquals($aud, $o->getCacheKey());
    }

    public function testIssuedAtDefaultsToNull()
    {
        $o = new OAuth2($this->minimal);
        $this->assertNull($o->getIssuedAt());
    }

    public function testExpiresAtDefaultsToNull()
    {
        $o = new OAuth2($this->minimal);
        $this->assertNull($o->getExpiresAt());
    }

    public function testExpiresInDefaultsToNull()
    {
        $o = new OAuth2($this->minimal);
        $this->assertNull($o->getExpiresIn());
    }

    public function testSettingExpiresInSetsIssuedAt()
    {
        $o = new OAuth2($this->minimal);
        $this->assertNull($o->getIssuedAt());
        $aShortWhile = 5;
        $o->setExpiresIn($aShortWhile);
        $this->assertEquals($aShortWhile, $o->getExpiresIn());
        $this->assertNotNull($o->getIssuedAt());
    }

    public function testSettingExpiresInSetsExpireAt()
    {
        $o = new OAuth2($this->minimal);
        $this->assertNull($o->getExpiresAt());
        $aShortWhile = 5;
        $o->setExpiresIn($aShortWhile);
        $this->assertNotNull($o->getExpiresAt());
        $this->assertEquals($aShortWhile, $o->getExpiresAt() - $o->getIssuedAt());
    }

    public function testIsNotExpiredByDefault()
    {
        $o = new OAuth2($this->minimal);
        $this->assertFalse($o->isExpired());
    }

    public function testIsNotExpiredIfExpiresAtIsOld()
    {
        $o = new OAuth2($this->minimal);
        $o->setExpiresAt(time() - 2);
        $this->assertTrue($o->isExpired());
    }

    public function testFailsOnUnknownSigningAlgorithm()
    {
        $this->expectException('InvalidArgumentException');
        $o = new OAuth2($this->minimal);
        $o->setSigningAlgorithm('this is definitely not an algorithm name');
    }

    public function testAllowsKnownSigningAlgorithms()
    {
        $o = new OAuth2($this->minimal);
        foreach (OAuth2::$knownSigningAlgorithms as $a) {
            $o->setSigningAlgorithm($a);
            $this->assertEquals($a, $o->getSigningAlgorithm());
        }
    }

    public function testFailsOnRelativeRedirectUri()
    {
        $this->expectException('InvalidArgumentException');
        $o = new OAuth2($this->minimal);
        $o->setRedirectUri('/relative/url');
    }

    public function testAllowsUrnRedirectUri()
    {
        $urn = 'urn:ietf:wg:oauth:2.0:oob';
        $o = new OAuth2($this->minimal);
        $o->setRedirectUri($urn);
        $this->assertEquals($urn, $o->getRedirectUri());
    }

    public function testFailsWithMissingAudience()
    {
        $this->expectException('DomainException');
        $testConfig = $this->signingMinimal;
        unset($testConfig['audience']);
        $o = new OAuth2($testConfig);
        $o->toJwt();
    }

    public function testFailsWithMissingIssuer()
    {
        $this->expectException('DomainException');
        $testConfig = $this->signingMinimal;
        unset($testConfig['issuer']);
        $o = new OAuth2($testConfig);
        $o->toJwt();
    }

    /**
     */
    public function testCanHaveNoScope()
    {
        $testConfig = $this->signingMinimal;
        unset($testConfig['scope']);
        $o = new OAuth2($testConfig);
        $o->toJwt();
    }

    public function testFailsWithMissingSigningKey()
    {
        $this->expectException('DomainException');
        $testConfig = $this->signingMinimal;
        unset($testConfig['signingKey']);
        $o = new OAuth2($testConfig);
        $o->toJwt();
    }

    public function testFailsWithMissingSigningAlgorithm()
    {
        $this->expectException('DomainException');
        $testConfig = $this->signingMinimal;
        unset($testConfig['signingAlgorithm']);
        $o = new OAuth2($testConfig);
        $o->toJwt();
    }

    public function testCanHS256EncodeAValidPayloadWithSigningKeyId()
    {
        $testConfig = $this->signingMinimal;
        $keys = array(
            'example_key_id1' => 'example_key1',
            'example_key_id2' => 'example_key2'
        );
        $testConfig['signingKey'] = $keys['example_key_id2'];
        $testConfig['signingKeyId'] = 'example_key_id2';
        $o = new OAuth2($testConfig);
        $payload = $o->toJwt();
        $roundTrip = $this->jwtDecode($payload, $keys, array('HS256'));
        $this->assertEquals($roundTrip->iss, $testConfig['issuer']);
        $this->assertEquals($roundTrip->aud, $testConfig['audience']);
        $this->assertEquals($roundTrip->scope, $testConfig['scope']);
    }

    public function testFailDecodeWithoutSigningKeyId()
    {
        $testConfig = $this->signingMinimal;
        $keys = array(
            'example_key_id1' => 'example_key1',
            'example_key_id2' => 'example_key2'
        );
        $testConfig['signingKey'] = $keys['example_key_id2'];
        $o = new OAuth2($testConfig);
        $payload = $o->toJwt();

        try {
            $this->jwtDecode($payload, $keys, array('HS256'));
        } catch (\Exception $e) {
            if (($e instanceof \DomainException || $e instanceof \UnexpectedValueException) &&
                $e->getMessage() === '"kid" empty, unable to lookup correct key') {
                // Workaround: In old JWT versions throws DomainException
                return;
            }
            throw $e;
        }
        $this->fail("Expected exception about problem with decode");
    }

    public function testCanHS256EncodeAValidPayload()
    {
        $testConfig = $this->signingMinimal;
        $o = new OAuth2($testConfig);
        $payload = $o->toJwt();
        $roundTrip = $this->jwtDecode($payload, $testConfig['signingKey'], array('HS256'));
        $this->assertEquals($roundTrip->iss, $testConfig['issuer']);
        $this->assertEquals($roundTrip->aud, $testConfig['audience']);
        $this->assertEquals($roundTrip->scope, $testConfig['scope']);
    }

    public function testCanRS256EncodeAValidPayload()
    {
        $testConfig = $this->signingMinimal;
        $o = new OAuth2($testConfig);
        $o->setSigningAlgorithm('RS256');
        $o->setSigningKey($this->privateKey);
        $payload = $o->toJwt();
        $roundTrip = $this->jwtDecode($payload, $this->publicKey, array('RS256'));
        $this->assertEquals($roundTrip->iss, $testConfig['issuer']);
        $this->assertEquals($roundTrip->aud, $testConfig['audience']);
        $this->assertEquals($roundTrip->scope, $testConfig['scope']);
    }

    public function testCanHaveAdditionalClaims()
    {
        $testConfig = $this->signingMinimal;
        $targetAud = '123@456.com';
        $testConfig['additionalClaims'] = ['target_audience' => $targetAud];
        $o = new OAuth2($testConfig);
        $o->setSigningAlgorithm('RS256');
        $o->setSigningKey($this->privateKey);
        $payload = $o->toJwt();
        $roundTrip = $this->jwtDecode($payload, $this->publicKey, array('RS256'));
        $this->assertEquals($roundTrip->target_audience, $targetAud);
    }

    public function testFailsIfNoTokenCredentialUri()
    {
        $this->expectException('DomainException');
        $testConfig = $this->tokenRequestMinimal;
        unset($testConfig['tokenCredentialUri']);
        $o = new OAuth2($testConfig);
        $o->generateCredentialsRequest();
    }

    public function testFailsIfAuthorizationCodeIsMissing()
    {
        $this->expectException('DomainException');
        $testConfig = $this->tokenRequestMinimal;
        $testConfig['redirectUri'] = 'https://has/redirect/uri';
        $o = new OAuth2($testConfig);
        $o->generateCredentialsRequest();
    }

    public function testGeneratesAuthorizationCodeRequests()
    {
        $testConfig = $this->tokenRequestMinimal;
        $testConfig['redirectUri'] = 'https://has/redirect/uri';
        $o = new OAuth2($testConfig);
        $o->setCode('an_auth_code');

        // Generate the request and confirm that it's correct.
        $req = $o->generateCredentialsRequest();
        $this->assertInstanceOf('Psr\Http\Message\RequestInterface', $req);
        $this->assertEquals('POST', $req->getMethod());
        $fields = Psr7\parse_query((string)$req->getBody());
        $this->assertEquals('authorization_code', $fields['grant_type']);
        $this->assertEquals('an_auth_code', $fields['code']);
    }

    public function testGeneratesPasswordRequests()
    {
        $testConfig = $this->tokenRequestMinimal;
        $o = new OAuth2($testConfig);
        $o->setUsername('a_username');
        $o->setPassword('a_password');

        // Generate the request and confirm that it's correct.
        $req = $o->generateCredentialsRequest();
        $this->assertInstanceOf('Psr\Http\Message\RequestInterface', $req);
        $this->assertEquals('POST', $req->getMethod());
        $fields = Psr7\parse_query((string)$req->getBody());
        $this->assertEquals('password', $fields['grant_type']);
        $this->assertEquals('a_password', $fields['password']);
        $this->assertEquals('a_username', $fields['username']);
    }

    public function testGeneratesRefreshTokenRequests()
    {
        $testConfig = $this->tokenRequestMinimal;
        $o = new OAuth2($testConfig);
        $o->setRefreshToken('a_refresh_token');

        // Generate the request and confirm that it's correct.
        $req = $o->generateCredentialsRequest();
        $this->assertInstanceOf('Psr\Http\Message\RequestInterface', $req);
        $this->assertEquals('POST', $req->getMethod());
        $fields = Psr7\parse_query((string)$req->getBody());
        $this->assertEquals('refresh_token', $fields['grant_type']);
        $this->assertEquals('a_refresh_token', $fields['refresh_token']);
    }

    public function testClientSecretAddedIfSetForAuthorizationCodeRequests()
    {
        $testConfig = $this->tokenRequestMinimal;
        $testConfig['clientSecret'] = 'a_client_secret';
        $testConfig['redirectUri'] = 'https://has/redirect/uri';
        $o = new OAuth2($testConfig);
        $o->setCode('an_auth_code');
        $request = $o->generateCredentialsRequest();
        $fields = Psr7\parse_query((string)$request->getBody());
        $this->assertEquals('a_client_secret', $fields['client_secret']);
    }

    public function testClientSecretAddedIfSetForRefreshTokenRequests()
    {
        $testConfig = $this->tokenRequestMinimal;
        $testConfig['clientSecret'] = 'a_client_secret';
        $o = new OAuth2($testConfig);
        $o->setRefreshToken('a_refresh_token');
        $request = $o->generateCredentialsRequest();
        $fields = Psr7\parse_query((string)$request->getBody());
        $this->assertEquals('a_client_secret', $fields['client_secret']);
    }

    public function testClientSecretAddedIfSetForPasswordRequests()
    {
        $testConfig = $this->tokenRequestMinimal;
        $testConfig['clientSecret'] = 'a_client_secret';
        $o = new OAuth2($testConfig);
        $o->setUsername('a_username');
        $o->setPassword('a_password');
        $request = $o->generateCredentialsRequest();
        $fields = Psr7\parse_query((string)$request->getBody());
        $this->assertEquals('a_client_secret', $fields['client_secret']);
    }

    public function testGeneratesAssertionRequests()
    {
        $testConfig = $this->tokenRequestMinimal;
        $o = new OAuth2($testConfig);
        $o->setSigningKey('a_key');
        $o->setSigningAlgorithm('HS256');

        // Generate the request and confirm that it's correct.
        $req = $o->generateCredentialsRequest();
        $this->assertInstanceOf('Psr\Http\Message\RequestInterface', $req);
        $this->assertEquals('POST', $req->getMethod());
        $fields = Psr7\parse_query((string)$req->getBody());
        $this->assertEquals(OAuth2::JWT_URN, $fields['grant_type']);
        $this->assertArrayHasKey('assertion', $fields);
    }

    public function testGeneratesExtendedRequests()
    {
        $testConfig = $this->tokenRequestMinimal;
        $o = new OAuth2($testConfig);
        $o->setGrantType('urn:my_test_grant_type');
        $o->setExtensionParams(['my_param' => 'my_value']);

        // Generate the request and confirm that it's correct.
        $req = $o->generateCredentialsRequest();
        $this->assertInstanceOf('Psr\Http\Message\RequestInterface', $req);
        $this->assertEquals('POST', $req->getMethod());
        $fields = Psr7\parse_query((string)$req->getBody());
        $this->assertEquals('my_value', $fields['my_param']);
        $this->assertEquals('urn:my_test_grant_type', $fields['grant_type']);
    }

    public function testFailsOn400()
    {
        $this->expectException('GuzzleHttp\Exception\ClientException');
        $testConfig = $this->fetchAuthTokenMinimal;
        $httpHandler = getHandler([
            buildResponse(400),
        ]);
        $o = new OAuth2($testConfig);
        $o->fetchAuthToken($httpHandler);
    }

    public function testFailsOn500()
    {
        $this->expectException('GuzzleHttp\Exception\ServerException');
        $testConfig = $this->fetchAuthTokenMinimal;
        $httpHandler = getHandler([
            buildResponse(500),
        ]);
        $o = new OAuth2($testConfig);
        $o->fetchAuthToken($httpHandler);
    }

    public function testFailsOnNoContentTypeIfResponseIsNotJSON()
    {
        $this->expectException('Exception');
        $this->expectExceptionMessage('Invalid JSON response');
        $testConfig = $this->fetchAuthTokenMinimal;
        $notJson = '{"foo": , this is cannot be passed as json" "bar"}';
        $httpHandler = getHandler([
            buildResponse(200, [], Psr7\stream_for($notJson)),
        ]);
        $o = new OAuth2($testConfig);
        $o->fetchAuthToken($httpHandler);
    }

    public function testFetchesJsonResponseOnNoContentTypeOK()
    {
        $testConfig = $this->fetchAuthTokenMinimal;
        $json = '{"foo": "bar"}';
        $httpHandler = getHandler([
            buildResponse(200, [], Psr7\stream_for($json)),
        ]);
        $o = new OAuth2($testConfig);
        $tokens = $o->fetchAuthToken($httpHandler);
        $this->assertEquals($tokens['foo'], 'bar');
    }

    public function testFetchesFromFormEncodedResponseOK()
    {
        $testConfig = $this->fetchAuthTokenMinimal;
        $json = 'foo=bar&spice=nice';
        $httpHandler = getHandler([
            buildResponse(
                200,
                ['Content-Type' => 'application/x-www-form-urlencoded'],
                Psr7\stream_for($json)
            ),
        ]);
        $o = new OAuth2($testConfig);
        $tokens = $o->fetchAuthToken($httpHandler);
        $this->assertEquals($tokens['foo'], 'bar');
        $this->assertEquals($tokens['spice'], 'nice');
    }

    public function testUpdatesTokenFieldsOnFetch()
    {
        $testConfig = $this->fetchAuthTokenMinimal;
        $wanted_updates = [
            'expires_at' => '1',
            'expires_in' => '57',
            'issued_at' => '2',
            'access_token' => 'an_access_token',
            'id_token' => 'an_id_token',
            'refresh_token' => 'a_refresh_token',
        ];
        $json = json_encode($wanted_updates);
        $httpHandler = getHandler([
            buildResponse(200, [], Psr7\stream_for($json)),
        ]);
        $o = new OAuth2($testConfig);
        $this->assertNull($o->getExpiresAt());
        $this->assertNull($o->getExpiresIn());
        $this->assertNull($o->getIssuedAt());
        $this->assertNull($o->getAccessToken());
        $this->assertNull($o->getIdToken());
        $this->assertNull($o->getRefreshToken());
        $tokens = $o->fetchAuthToken($httpHandler);
        $this->assertEquals(1, $o->getExpiresAt());
        $this->assertEquals(57, $o->getExpiresIn());
        $this->assertEquals(2, $o->getIssuedAt());
        $this->assertEquals('an_access_token', $o->getAccessToken());
        $this->assertEquals('an_id_token', $o->getIdToken());
        $this->assertEquals('a_refresh_token', $o->getRefreshToken());
    }

    public function testUpdatesTokenFieldsOnFetchMissingRefreshToken()
    {
        $testConfig = $this->fetchAuthTokenMinimal;
        $testConfig['refresh_token'] = 'a_refresh_token';
        $wanted_updates = [
            'expires_at' => '1',
            'expires_in' => '57',
            'issued_at' => '2',
            'access_token' => 'an_access_token',
            'id_token' => 'an_id_token',
        ];
        $json = json_encode($wanted_updates);
        $httpHandler = getHandler([
            buildResponse(200, [], Psr7\stream_for($json)),
        ]);
        $o = new OAuth2($testConfig);
        $this->assertNull($o->getExpiresAt());
        $this->assertNull($o->getExpiresIn());
        $this->assertNull($o->getIssuedAt());
        $this->assertNull($o->getAccessToken());
        $this->assertNull($o->getIdToken());
        $this->assertEquals('a_refresh_token', $o->getRefreshToken());
        $tokens = $o->fetchAuthToken($httpHandler);
        $this->assertEquals(1, $o->getExpiresAt());
        $this->assertEquals(57, $o->getExpiresIn());
        $this->assertEquals(2, $o->getIssuedAt());
        $this->assertEquals('an_access_token', $o->getAccessToken());
        $this->assertEquals('an_id_token', $o->getIdToken());
        $this->assertEquals('a_refresh_token', $o->getRefreshToken());
    }

    public function testFailsIfIdTokenIsInvalid()
    {
        $this->expectException('UnexpectedValueException');
        $testConfig = $this->verifyIdTokenMinimal;
        $not_a_jwt = 'not a jot';
        $o = new OAuth2($testConfig);
        $o->setIdToken($not_a_jwt);
        $o->verifyIdToken($this->publicKey);
    }

    public function testFailsIfAudienceIsMissing()
    {
        $this->expectException('DomainException');
        $testConfig = $this->verifyIdTokenMinimal;
        $now = time();
        $origIdToken = [
            'issuer' => $testConfig['issuer'],
            'exp' => $now + 65, // arbitrary
            'iat' => $now,
        ];
        $o = new OAuth2($testConfig);
        $jwtIdToken = $this->jwtEncode($origIdToken, $this->privateKey, 'RS256');
        $o->setIdToken($jwtIdToken);
        $o->verifyIdToken($this->publicKey, ['RS256']);
    }

    public function testFailsIfAudienceIsWrong()
    {
        $this->expectException('DomainException');
        $now = time();
        $testConfig = $this->verifyIdTokenMinimal;
        $origIdToken = [
            'aud' => 'a different audience',
            'iss' => $testConfig['issuer'],
            'exp' => $now + 65, // arbitrary
            'iat' => $now,
        ];
        $o = new OAuth2($testConfig);
        $jwtIdToken = $this->jwtEncode($origIdToken, $this->privateKey, 'RS256');
        $o->setIdToken($jwtIdToken);
        $o->verifyIdToken($this->publicKey, ['RS256']);
    }

    public function testShouldReturnAValidIdToken()
    {
        $testConfig = $this->verifyIdTokenMinimal;
        $now = time();
        $origIdToken = [
            'aud' => $testConfig['audience'],
            'iss' => $testConfig['issuer'],
            'exp' => $now + 65, // arbitrary
            'iat' => $now,
        ];
        $o = new OAuth2($testConfig);
        $alg = 'RS256';
        $jwtIdToken = $this->jwtEncode($origIdToken, $this->privateKey, $alg);
        $o->setIdToken($jwtIdToken);
        $roundTrip = $o->verifyIdToken($this->publicKey, array($alg));
        $this->assertEquals($origIdToken['aud'], $roundTrip->aud);
    }

    /**
     * @dataProvider provideRevoke
     */
    public function testRevoke($input, $expected)
    {
        $httpClient = httpClientFromCallable(function (RequestInterface $request) use ($expected) {
            $this->assertEquals('no-store', $request->getHeaderLine('Cache-Control'));
            $this->assertEquals('application/x-www-form-urlencoded', $request->getHeaderLine('Content-Type'));
            $this->assertEquals('POST', $request->getMethod());
            $this->assertEquals(GoogleAuth::OAUTH2_REVOKE_URI, (string) $request->getUri());
            $this->assertEquals('token=' . $expected, (string) $request->getBody());

            return new Response(200);
        });

        $oauth = new OAuth2([
            'httpClient' => $httpClient,
        ]);

        $this->assertTrue($oauth->revoke($input));
    }

    public function provideRevoke()
    {
        $testToken = 'testtoken';
        return [
            [
                $testToken,
                $testToken
            ], [
                ['refresh_token' => $testToken, 'access_token' => 'other thing'],
                $testToken
            ], [
                ['access_token' => $testToken],
                $testToken
            ]
        ];
    }

    public function testRevokeFails()
    {
        $httpClient = httpClientFromCallable(function (RequestInterface $request) {
            return new Response(500);
        });

        $oauth = new OAuth2([
            'httpClient' => $httpClient,
        ]);

        $this->assertFalse($oauth->revoke('testtoken'));
    }
}