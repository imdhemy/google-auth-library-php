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

use Google\Auth\SignBlob\ServiceAccountApiSignBlobTrait;
use Google\Auth\SignBlob\PrivateKeySignBlobTrait;
use Google\Auth\SignBlob\SignBlobInterface;
use Google\Auth\OAuth2;
use InvalidArgumentException;

/**
 * ServiceAccountCredentials supports authorization using a Google service
 * account.
 *
 * (cf https://developers.google.com/accounts/docs/OAuth2ServiceAccount)
 *
 * It's initialized using the json key file that's downloadable from developer
 * console, which should contain a private_key and client_email fields that it
 * uses.
 *
 * Use it with AuthTokenMiddleware to authorize http requests:
 *
 *   use Google\Auth\Credentials\ServiceAccountCredentials;
 *   use Google\Auth\Middleware\AuthTokenMiddleware;
 *   use GuzzleHttp\Client;
 *   use GuzzleHttp\HandlerStack;
 *
 *   $sa = new ServiceAccountCredentials(
 *       'https://www.googleapis.com/auth/taskqueue',
 *       '/path/to/your/json/key_file.json'
 *   );
 *   $middleware = new AuthTokenMiddleware($sa);
 *   $stack = HandlerStack::create();
 *   $stack->push($middleware);
 *
 *   $client = new Client([
 *       'handler' => $stack,
 *       'base_uri' => 'https://www.googleapis.com/taskqueue/v1beta2/projects/',
 *       'auth' => 'google_auth' // authorize all requests
 *   ]);
 *
 *   $res = $client->get('myproject/taskqueues/myqueue');
 */
class ServiceAccountCredentials implements
    CredentialsInterface,
    SignBlobInterface
{
    use CredentialsTrait {
        CredentialsTrait::getRequestMetadata as traitGetRequestMetadata;
    }
    use PrivateKeySignBlobTrait;
    use ServiceAccountApiSignBlobTrait;

    /**
     * The OAuth2 instance used to conduct authorization.
     *
     * @var OAuth2
     */
    private $oauth2;

    /**
     * The quota project associated with the JSON credentials
     *
     * @var string
     */
    private $quotaProject;

    /*
     * @var string|null
     */
    private $projectId;

    /**
     * Create a new ServiceAccountCredentials.
     *
     * @param string|array $jsonKey JSON credential file path or JSON
     *      credentials in associative array
     * @param array $options {
     *      @type string|array $scope the scope of the access request, expressed
     *          as an array or as a space-delimited string.
     *      @type string $sub an email address account to impersonate, in situations
     *          when the service account has been delegated domain wide access.
     *      @type string $targetAudience The audience for the ID token.
     * }
     */
    public function __construct($jsonKey, array $options = [])
    {
        $options += [
            'scope' => null,
            'targetAudience' => null,
            'subject' => null,
        ];

        if (is_string($jsonKey)) {
            if (!file_exists($jsonKey)) {
                throw new \InvalidArgumentException('file does not exist');
            }
            $jsonKeyStream = file_get_contents($jsonKey);
            if (!$jsonKey = json_decode($jsonKeyStream, true)) {
                throw new \LogicException('invalid json for auth config');
            }
        }
        if (!array_key_exists('client_email', $jsonKey)) {
            throw new \InvalidArgumentException(
                'json key is missing the client_email field'
            );
        }
        if (!array_key_exists('private_key', $jsonKey)) {
            throw new \InvalidArgumentException(
                'json key is missing the private_key field'
            );
        }
        if (isset($jsonKey['quota_project_id'])) {
            $this->quotaProject = (string) $jsonKey['quota_project_id'];
        }
        if ($options['scope'] && $options['targetAudience']) {
            throw new InvalidArgumentException(
                'Scope and targetAudience cannot both be supplied'
            );
        }
        $additionalClaims = [];
        if ($options['targetAudience']) {
            $additionalClaims = [
                'target_audience' => $options['targetAudience']
            ];
        }
        $this->setHttpClientFromOptions($options);
        $this->oauth2 = new OAuth2([
            'audience' => self::TOKEN_CREDENTIAL_URI,
            'tokenCredentialUri' => self::TOKEN_CREDENTIAL_URI,
            'signingAlgorithm' => 'RS256',
            'signingKey' => $jsonKey['private_key'],
            'issuer' => $jsonKey['client_email'],
            'scope' => $options['scope'],
            'sub' => $options['subject'],
            'additionalClaims' => $additionalClaims,
            'httpClient' => $this->httpClient,
        ]);

        $this->projectId = isset($jsonKey['project_id'])
            ? $jsonKey['project_id']
            : null;
    }

    /**
     * @return array A set of auth related metadata, with the following keys:
     *     - access_token (string)
     *     - expires_in (int)
     *     - token_type (string)
     */
    public function fetchAuthToken(): array
    {
        return $this->oauth2->fetchAuthToken();
    }

    /**
     * Get the project ID from the service account keyfile.
     *
     * Returns null if the project ID does not exist in the keyfile.
     *
     * @return string|null
     */
    public function getProjectId(): ?string
    {
        return $this->projectId;
    }

    /**
     * Returns request metadata with the authorization token.
     *
     * @param callable $httpHandler callback which delivers psr7 request
     * @return array metadata hashmap for request headers
     */
    public function getRequestMetadata(
        ClientInterface $httpHandler = null
    ): array {
        // scope exists. use oauth implementation
        if (!$this->useSelfSignedJwt()) {
            return $this->traitGetRequestMetadata($httpHandler);
        }

        // no scope found. create jwt with the auth uri
        $credJson = array(
            'private_key' => $this->oauth2->getSigningKey(),
            'client_email' => $this->oauth2->getIssuer(),
        );
        $jwtCreds = new ServiceAccountJwtAccessCredentials($credJson);

        $updatedMetadata = $jwtCreds->getRequestMetadata($httpHandler);

        return $updatedMetadata;
    }

    /**
     * @param string $sub an email address account to impersonate, in situations when
     *   the service account has been delegated domain wide access.
     */
    public function setSub($sub)
    {
        $this->oauth2->setSub($sub);
    }

    /**
     * Sign a string using the method which is best for a given credentials type.
     * If OpenSSL is not installed, uses the Service Account Credentials API.
     *
     * @param string $stringToSign The string to sign.
     * @return string The resulting signature. Value should be base64-encoded.
     */
    public function signBlob(string $stringToSign): string
    {
        try {
            return $this->signBlobWithPrivateKey(
                $stringToSign,
                $this->oauth2->getSigningKey()
            );
        } catch (\RuntimeException $e) {
        }

        $accessToken = $this->fetchAuthToken()['access_token'];
        return $this->signBlobWithServiceAccountApi(
            $this->httpClient,
            $this->getClientEmail(),
            $accessToken,
            $stringToSign
        );
    }

    /**
     * Get the client name from the keyfile.
     *
     * In this case, it returns the keyfile's client_email key.
     *
     * @return string
     */
    public function getClientEmail(): string
    {
        return $this->oauth2->getIssuer();
    }


    private function useSelfSignedJwt()
    {
        return is_null($this->oauth2->getScope());
    }

    /**
     * Get the quota project used for this API request
     *
     * @return string|null
     */
    public function getQuotaProject(): ?string
    {
        return $this->quotaProject;
    }
}
