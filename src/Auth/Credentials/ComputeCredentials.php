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

use Google\Auth\GetQuotaProjectInterface;
use Google\Auth\Http\ClientFactory;
use Google\Auth\HttpHandler\HttpClientCache;
use Google\Auth\HttpHandler\HttpHandlerFactory;
use Google\Auth\ProjectIdProviderInterface;
use Google\Auth\SignBlob\SignBlobInterface;
use Google\Auth\SignBlob\ServiceAccountApiSignBlobTrait;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Exception\ServerException;
use GuzzleHttp\Psr7\Request;
use InvalidArgumentException;

/**
 * ComputeCredentials supports authorization on Google Compute Engine.
 *
 * It can be used to authorize requests using the AuthTokenMiddleware, but will
 * only succeed if being run on GCE:
 *
 *   use Google\Auth\Credentials\ComputeCredentials;
 *   use Google\Auth\Http\CredentialsClient;
 *   use Psr\Http\Message\Request;
 *
 *   $gce = new ComputeCredentials();
 *   $http = new CredentialsClient($gce);
 *
 *   $url = 'https://www.googleapis.com/taskqueue/v1beta2/projects';
 *   $res = $http->send(new Request('GET', $url));
 */
class ComputeCredentials implements
    CredentialsInterface,
    SignBlobInterface
{
    use CredentialsTrait, ServiceAccountApiSignBlobTrait;

    /**
     * The metadata IP address on appengine instances.
     *
     * The IP is used instead of the domain 'metadata' to avoid slow responses
     * when not on Compute Engine.
     */
    private const METADATA_IP = '169.254.169.254';

    /**
     * The metadata path of the default token.
     */
    private const TOKEN_URI_PATH = 'v1/instance/service-accounts/default/token';

    /**
     * The metadata path of the default id token.
     */
    private const ID_TOKEN_URI_PATH = 'v1/instance/service-accounts/default/identity';

    /**
     * The metadata path of the client ID.
     */
    private const CLIENT_EMAIL_URI_PATH = 'v1/instance/service-accounts/default/email';

    /**
     * The metadata path of the project ID.
     */
    private const PROJECT_ID_URI_PATH = 'v1/project/project-id';

    /**
     * The header whose presence indicates GCE presence.
     */
    private const FLAVOR_HEADER = 'Metadata-Flavor';

    /**
     * Flag used to ensure that the onGCE test is only done once;.
     *
     * @var bool
     */
    private $hasCheckedOnGce = false;

    /**
     * Flag that stores the value of the onGCE check.
     *
     * @var bool
     */
    private $isOnGce = false;


    /**
     * @var string|null
     */
    private $clientEmail;

    /**
     * @var string|null
     */
    private $projectId;

    /**
     * @var string
     */
    private $tokenUri;

    /**
     * @var string
     */
    private $targetAudience;

    /**
     * @var string|null
     */
    private $quotaProject;

    /**
     * @var string|null
     */
    private $serviceAccountIdentity;

    /**
     * @var ClientInterface
     */
    private $httpClient;

    /**
     * @param array $options {
     *     @type string|array $scope the scope of the access request,
     *         expressed either as an array or as a space-delimited string.
     *     @type string $targetAudience The audience for the ID token.
     *     @type string $quotaProject Specifies a project to bill for access
     *         charges associated with the request.
     *     @type string $serviceAccountIdentity [optional] Specify a service
     *         account identity name to use instead of "default".
     * }
     */
    public function __construct(array $options = [])
    {
        $options += [
            'scope' => null,
            'targetAudience' => null,
            'quotaProject' => null,
            'httpClient' => null,
            'serviceAccountIdentity' => null,
            'cache' => null,
            'lifetime' => null,
        ];

        if (isset($options['scope']) && isset($options['targetAudience'])) {
            throw new InvalidArgumentException(
                'Scope and targetAudience cannot both be supplied'
            );
        }

        $tokenUri = self::getTokenUri($options['serviceAccountIdentity']);
        if ($options['scope']) {
            if (is_string($options['scope'])) {
                $options['scope'] = explode(' ', $options['scope']);
            }

            $options['scope'] = implode(',', $options['scope']);
            $tokenUri = $tokenUri . '?scopes='. $options['scope'];
        } elseif ($options['targetAudience']) {
            $tokenUri = self::getIdTokenUri($options['serviceAccountIdentity']);
            $tokenUri = sprintf(
                'http://%s/computeMetadata/%s?audience=%s',
                self::METADATA_IP,
                self::ID_TOKEN_URI_PATH,
                $options['targetAudience']
            );
            $this->targetAudience = $options['targetAudience'];
        }

        $this->tokenUri = $tokenUri;

        $this->quotaProject = $options['quotaProject'];
        $this->httpClient = $options['httpClient'] ?: ClientFactory::build();
        $this->serviceAccountIdentity = $options['serviceAccountIdentity'];
    }

    /**
     * The full uri for accessing the default token.
     *
     * @param strin|null $serviceAccountIdentity [optional] Specify a service
     *   account identity name to use instead of "default".
     * @return string
     */

    public static function getTokenUri(
        string $serviceAccountIdentity = null
    ): string {
        $base = 'http://' . self::METADATA_IP . '/computeMetadata/';
        $base .= self::TOKEN_URI_PATH;

        if ($serviceAccountIdentity) {
            return str_replace(
                '/default/',
                '/' . $serviceAccountIdentity . '/',
                $base
            );
        }
        return $base;
    }

    /**
     * Determines if this an App Engine Flexible instance, by accessing the
     * GAE_INSTANCE environment variable.
     *
     * @return bool
     */
    public static function onAppEngineFlexible(): bool
    {
        return substr(getenv('GAE_INSTANCE'), 0, 4) === 'aef-';
    }

    /**
     * Determines if this a GCE instance, by accessing the expected metadata
     * host.
     *
     * @param ClientInterface $httpClient
     * @return bool
     */
    public static function onGce(): bool
    {
        $checkUri = 'http://' . self::METADATA_IP;
        for ($i = 1; $i <= self::MAX_COMPUTE_PING_TRIES; $i++) {
            try {
                // Comment from: oauth2client/client.py
                //
                // Note: the explicit `timeout` below is a workaround. The underlying
                // issue is that resolving an unknown host on some networks will take
                // 20-30 seconds; making this timeout short fixes the issue, but
                // could lead to false negatives in the event that we are on GCE, but
                // the metadata resolution was particularly slow. The latter case is
                // "unlikely".
                $resp = $this->httpClient->send(
                    new Request(
                        'GET',
                        $checkUri,
                        [self::FLAVOR_HEADER => 'Google']
                    ),
                    ['timeout' => self::COMPUTE_PING_CONNECTION_TIMEOUT_S]
                );

                return $resp->getHeaderLine(self::FLAVOR_HEADER) == 'Google';
            } catch (ClientException $e) {
            } catch (ServerException $e) {
            } catch (RequestException $e) {
            } catch (ConnectException $e) {
            }
        }
        return false;
    }

    /**
     * Implements FetchAuthTokenInterface#fetchAuthToken.
     *
     * Fetches the auth tokens from the GCE metadata host if it is available.
     * If $httpClient is not specified a the default HttpHandler is used.
     *
     * @param ClientInterface $httpClient callback which delivers psr7 request
     *
     * @return array A set of auth related metadata, based on the token type.
     *
     * Access tokens have the following keys:
     *   - access_token (string)
     *   - expires_in (int)
     *   - token_type (string)
     * ID tokens have the following keys:
     *   - id_token (string)
     *
     * @throws \Exception
     */
    public function fetchAuthToken(): array
    {
        if (!$this->isOnGce($this->httpClient)) {
            return [];  // return an empty array with no access token
        }

        $response = $this->getFromMetadata($this->tokenUri);

        if ($this->targetAudience) {
            return ['id_token' => $response];
        }

        if (null === $json = json_decode($response, true)) {
            throw new \Exception('Invalid JSON response');
        }

        $json['expires_at'] = time() + $json['expires_in'];

        // store this so we can retrieve it later
        $this->lastReceivedToken = $json;

        return $json;
    }

    /**
     * Get the client name from GCE metadata.
     *
     * Subsequent calls will return a cached value.
     *
     * @return string
     */
    public function getClientEmail(): string
    {
        if ($this->clientEmail) {
            return $this->clientEmail;
        }

        if (!$this->isOnGce($this->httpClient)) {
            return '';
        }

        return $this->clientEmail = $this->getFromMetadata(
            self::getClientEmailUri($this->serviceAccountIdentity)
        );
    }

    /**
     * Sign a string using the default service account private key.
     *
     * This implementation uses IAM's signBlob API.
     *
     * @see https://cloud.google.com/iam/credentials/reference/rest/v1/projects.serviceAccounts/signBlob SignBlob
     *
     * @param string $stringToSign The string to sign.
     * @return string
     */
    public function signBlob(string $stringToSign): string
    {
        $accessToken = $this->fetchAuthToken()['access_token'];

        return $this->signBlobWithServiceAccountApi(
            $this->getClientEmail(),
            $accessToken,
            $stringToSign,
            $this->httpClient
        );
    }

    /**
     * Fetch the default Project ID from compute engine.
     *
     * Returns null if called outside GCE.
     *
     * @return string|null
     */
    public function getProjectId(): ?string
    {
        if ($this->projectId) {
            return $this->projectId;
        }

        if (!$this->isOnGce($this->httpClient)) {
            return null;
        }

        return $this->projectId = $this->getFromMetadata(
            self::getProjectIdUri()
        );
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

    private function isOnGce(): bool
    {
        if (!$this->hasCheckedOnGce) {
            $this->isOnGce = self::onGce($this->httpClient);
            $this->hasCheckedOnGce = true;
        }

        return $this->isOnGce;
    }

    /**
     * Fetch the value of a GCE metadata server URI.
     *
     * @param string $uri The metadata URI.
     * @return string
     */
    private function getFromMetadata($uri)
    {
        $httpClient = $this->httpClient;
        $resp = $httpClient(
            new Request(
                'GET',
                $uri,
                [self::FLAVOR_HEADER => 'Google']
            )
        );

        return (string) $resp->getBody();
    }

    /**
     * The full uri for accessing the default project ID.
     *
     * @return string
     */
    private static function getProjectIdUri(): string
    {
        $base = 'http://' . self::METADATA_IP . '/computeMetadata/';

        return $base . self::PROJECT_ID_URI_PATH;
    }

    /**
     * The full uri for accessing the default service account.
     *
     * @param string $serviceAccountIdentity [optional] Specify a service
     *   account identity name to use instead of "default".
     * @return string
     */

    private static function getClientEmailUri(
        string $serviceAccountIdentity = null
    ): string {
        $base = 'http://' . self::METADATA_IP . '/computeMetadata/';
        $base .= self::CLIENT_EMAIL_URI_PATH;

        if ($serviceAccountIdentity) {
            return str_replace(
                '/default/',
                '/' . $serviceAccountIdentity . '/',
                $base
            );
        }

        return $base;
    }

    /**
     * The full uri for accesesing the default identity token.
     *
     * @param string $serviceAccountIdentity [optional] Specify a service
     *   account identity name to use instead of "default".
     * @return string
     */
    private static function getIdTokenUri($serviceAccountIdentity = null): string
    {
        $base = 'http://' . self::METADATA_IP . '/computeMetadata/';
        $base .= self::ID_TOKEN_URI_PATH;
        if ($serviceAccountIdentity) {
            return str_replace(
                '/default/',
                '/' . $serviceAccountIdentity . '/',
                $base
            );
        }

        return $base;

    }
}
