<?php
/*
 * Copyright 2020 Google Inc.
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

namespace Google\Auth;

use DomainException;
use Google\Auth\Credentials\ComputeCredentials;
use Google\Auth\Credentials\ServiceAccountCredentials;
use Google\Auth\Credentials\ServiceAccountJwtAccessCredentials;
use Google\Auth\Credentials\CredentialsInterface;
use Google\Auth\Http\ClientFactory;
use Google\Cache\MemoryCacheItemPool;
use InvalidArgumentException;
use Psr\Cache\CacheItemPoolInterface;

/**
 * GoogleAuth obtains the default credentials for
 * authorizing a request to a Google service.
 *
 * Application Default Credentials are described here:
 * https://developers.google.com/accounts/docs/application-default-credentials
 *
 * This class implements the search for the application default credentials as
 * described in the link.
 *
 * It provides three factory methods:
 * - #get returns the computed credentials object
 * - #getMiddleware returns an AuthTokenMiddleware built from the credentials object
 *
 * This allows it to be used as follows with GuzzleHttp\Client:
 *
 * ```
 * use Google\Auth\GoogleAuth;
 * use GuzzleHttp\Client;
 * use GuzzleHttp\HandlerStack;
 *
 * $auth = new GoogleAuth();
 * $middleware = $auth->getMiddleware(
 *     'https://www.googleapis.com/auth/taskqueue'
 * );
 * $stack = HandlerStack::create();
 * $stack->push($middleware);
 *
 * $client = new Client([
 *     'handler' => $stack,
 *     'base_uri' => 'https://www.googleapis.com/taskqueue/v1beta2/projects/',
 *     'auth' => 'google_auth' // authorize all requests
 * ]);
 *
 * $res = $client->get('myproject/taskqueues/myqueue');
 * ```
 */
class GoogleAuth
{
    private const TOKEN_REVOKE_URI = 'https://oauth2.googleapis.com/revoke';
    private const OIDC_CERT_URI = 'https://www.googleapis.com/oauth2/v3/certs';
    private const OIDC_ISSUERS = ['accounts.google.com', 'https://accounts.google.com'];
    private const IAP_JWK_URI = 'https://www.gstatic.com/iap/verify/public_key-jwk';
    private const IAP_ISSUERS = ['https://cloud.google.com/iap'];

    private const ENV_VAR = 'GOOGLE_APPLICATION_CREDENTIALS';
    private const WELL_KNOWN_PATH = 'gcloud/application_default_credentials.json';
    private const NON_WINDOWS_WELL_KNOWN_PATH_BASE = '.config';

    private $httpClient;
    private $cache;
    private $cacheLifetime;
    private $cachePrefix;

    /**
     * Obtains an AuthTokenMiddleware which will fetch an access token to use in
     * the Authorization header. The middleware is configured with the default
     * FetchAuthTokenInterface implementation to use in this environment.
     *
     * If supplied, $scope is used to in creating the credentials instance if
     * this does not fallback to the Compute Engine defaults.
     *
     * @param array $options {
     *      @type ClientInterface $httpClient client which delivers psr7 request
     *      @type CacheItemPoolInterface $cache A cache implementation, may be
     *             provided if you have one already available for use.
     *      @type int $cacheLifetime
     *      @type string $cachePrefix
     * }
     */
    public function __construct(array $options = [])
    {
        $options += [
            'httpClient' => null,
            'cache' => null,
            'cacheLifetime' => 1500,
            'cachePrefix' => '',
        ];

        $this->httpClient = $options['httpClient'] ?: ClientFactory::build();
        $this->cache = $options['cachePrefix'] ?: new MemoryCacheItemPool();
        $this->cacheLifetme = $options['cacheLifetime'];
        $this->cachePrefix = $options['cachePrefix'];
    }

    /**
     * Obtains an AuthTokenMiddleware which will fetch an access token to use in
     * the Authorization header. The middleware is configured with the default
     * FetchAuthTokenInterface implementation to use in this environment.
     *
     * If supplied, $scope is used to in creating the credentials instance if
     * this does not fallback to the Compute Engine defaults.
     *
     * @param array $options {
     *      @type string|array scope the scope of the access request, expressed
     *             either as an Array or as a space-delimited String.
     *      @type string $targetAudience The audience for the ID token.
     *      @type string $audience
     *      @type string $quotaProject specifies a project to bill for access
     *        charges associated with the request.
     *      @type string $subject
     * }
     * @return CredentialsInterface
     * @throws DomainException if no implementation can be obtained.
     */
    public function makeCredentials(array $options = []): CredentialsInterface
    {
        $options += [
            'scope' => null,
            'targetAudience' => null,
            'audience' => null,
            'quotaProject' => null,
            'subject' => null,
            'credentialsFile' => null,
        ];
        if (is_null($options['credentialsFile'])) {
            $jsonKey = self::fromEnv() ?: self::fromWellKnownFile();
        } else {
            if (!file_exists($options['credentialsFile'])) {
                throw new InvalidArgumentException('Unable to read credentialsFile');
            }
            $creds = file_get_contents($options['credentialsFile']);
            $jsonKey = json_decode($creds, true);
        }

        $creds = null;
        if (!is_null($jsonKey)) {
            if (!array_key_exists('type', $jsonKey)) {
                throw new \InvalidArgumentException('json key is missing the type field');
            }

            // Set quota project on jsonKey if passed in
            if (isset($options['quotaProject'])) {
                $jsonKey['quota_project'] = $options['quotaProject'];
            }

            switch ($jsonKey['type']) {
                case 'service_account':
                    if ($options['audience']) {
                        $creds = new ServiceAccountJwtAccessCredentials(
                            $jsonKey,
                            [
                                'httpClient' => $this->httpClient,
                                'audience' => $options['audience'],
                            ]
                        );
                    } else {
                        $creds = new ServiceAccountCredentials($jsonKey, [
                            'scope' => $options['scope'],
                            'targetAudience' => $options['targetAudience'],
                            'httpClient' => $this->httpClient,
                            'subject' => $options['subject'],
                        ]);
                    }
                    break;
                case 'authorized_user':
                    if (isset($options['targetAudience'])) {
                        throw new InvalidArgumentException(
                            'ID tokens are not supported for end user credentials'
                        );
                    }
                    $creds = new UserRefreshCredentials($jsonKey, [
                        'scope' => $options['scope'],
                    ]);
                    break;
                default:
                    throw new \InvalidArgumentException(
                        'invalid value in the type field'
                    );
            }
        } elseif ($this->onCompute()) {
            $creds = new ComputeCredentials([
                'scope' => $options['scope'],
                'quotaProject' => $options['quotaProject'],
                'httpClient' => $this->httpClient,
            ]);
        }

        if (is_null($creds)) {
            throw new DomainException(
                'Could not load the default credentials. Browse to '
                . 'https://developers.google.com/accounts/docs/application-default-credentials'
                . ' for more information'
            );
        }

        return $creds;
    }

    /**
     * Determines if this a GCE instance, by accessing the expected metadata
     * host.
     *
     * @return bool
     */
    public function onCompute(): bool
    {
        /**
         * Note: the explicit `timeout` and `tries` below is a workaround. The underlying
         * issue is that resolving an unknown host on some networks will take
         * 20-30 seconds; making this timeout short fixes the issue, but
         * could lead to false negatives in the event that we are on GCE, but
         * the metadata resolution was particularly slow. The latter case is
         * "unlikely" since the expected 4-nines time is about 0.5 seconds.
         * This allows us to limit the total ping maximum timeout to 1.5 seconds
         * for developer desktop scenarios.
         */
        $maxComputePingTries = 3;
        $computePingConnectionTimeoutSeconds = 0.5;
        $checkUri = 'http://' . ComputeCredentials::METADATA_IP;
        for ($i = 1; $i <= $maxComputePingTries; $i++) {
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
                    ['timeout' => $computePingConnectionTimeoutSeconds]
                );

                return $resp->getHeaderLine(self::FLAVOR_HEADER) == 'Google';
            } catch (ClientException $e) {
            } catch (ServerException $e) {
            } catch (RequestException $e) {
            }
        }
        return false;
    }

    /**
     * Gets federated sign-on certificates to use for verifying identity tokens.
     * Returns certs as array structure, where keys are key ids, and values
     * are PEM encoded certificates.
     *
     * @param string $location The location from which to retrieve certs.
     * @param string $cacheKey The key under which to cache the retrieved certs.
     * @param array $options [optional] Configuration options.
     * @return array
     * @throws InvalidArgumentException If received certs are in an invalid format.
     */
    private function getCerts($location, $cacheKey, array $options = [])
    {
        $cacheItem = $this->cache->getItem($cacheKey);
        $certs = $cacheItem ? $cacheItem->get() : null;

        $gotNewCerts = false;
        if (!$certs) {
            $certs = $this->retrieveCertsFromLocation($location, $options);

            $gotNewCerts = true;
        }

        if (!isset($certs['keys'])) {
            if ($location !== self::IAP_CERT_URL) {
                throw new InvalidArgumentException(
                    'federated sign-on certs expects "keys" to be set'
                );
            }
            throw new InvalidArgumentException(
                'certs expects "keys" to be set'
            );
        }

        // Push caching off until after verifying certs are in a valid format.
        // Don't want to cache bad data.
        if ($gotNewCerts) {
            $cacheItem->expiresAt(new DateTime('+1 hour'));
            $cacheItem->set($certs);
            $this->cache->save($cacheItem);
        }

        return $certs['keys'];
    }

    /**
     * Retrieve and cache a certificates file.
     *
     * @param $url string location
     * @param array $options [optional] Configuration options.
     * @return array certificates
     * @throws InvalidArgumentException If certs could not be retrieved from a local file.
     * @throws RuntimeException If certs could not be retrieved from a remote location.
     */
    private function retrieveCertsFromLocation($url, array $options = [])
    {
        // If we're retrieving a local file, just grab it.
        if (strpos($url, 'http') !== 0) {
            if (!file_exists($url)) {
                throw new InvalidArgumentException(sprintf(
                    'Failed to retrieve verification certificates from path: %s.',
                    $url
                ));
            }

            return json_decode(file_get_contents($url), true);
        }

        $response = $this->httpClient->send(new Request('GET', $url), $options);

        if ($response->getStatusCode() == 200) {
            return json_decode((string) $response->getBody(), true);
        }

        throw new RuntimeException(sprintf(
            'Failed to retrieve verification certificates: "%s".',
            $response->getBody()->getContents()
        ), $response->getStatusCode());
    }

    /**
     * Generate a cache key based on the cert location using sha1 with the
     * exception of using "federated_signon_certs_v3" to preserve BC.
     *
     * @param string $certsLocation
     * @return string
     */
    private function getCacheKeyFromCertLocation($certsLocation)
    {
        $key = $certsLocation === self::FEDERATED_SIGNON_CERT_URL
            ? 'federated_signon_certs_v3'
            : sha1($certsLocation);

        return 'google_auth_certs_cache|' . $key;
    }

    /**
     * Load a JSON key from the path specified in the environment.
     *
     * Load a JSON key from the path specified in the environment
     * variable GOOGLE_APPLICATION_CREDENTIALS. Return null if
     * GOOGLE_APPLICATION_CREDENTIALS is not specified.
     *
     * @return array|null
     */
    public static function fromEnv(): ?array
    {
        $path = getenv(self::ENV_VAR);
        if (empty($path)) {
            return null;
        }
        if (!file_exists($path)) {
            $cause = 'file ' . $path . ' does not exist';
            throw new \DomainException(self::unableToReadEnv($cause));
        }
        $jsonKey = file_get_contents($path);
        return json_decode($jsonKey, true);
    }

    /**
     * Load a JSON key from a well known path.
     *
     * The well known path is OS dependent:
     *
     * * windows: %APPDATA%/gcloud/application_default_credentials.json
     * * others: $HOME/.config/gcloud/application_default_credentials.json
     *
     * If the file does not exist, this returns null.
     *
     * @return array|null
     */
    public static function fromWellKnownFile(): ?array
    {
        $rootEnv = self::isOnWindows() ? 'APPDATA' : 'HOME';
        $path = [getenv($rootEnv)];
        if (!self::isOnWindows()) {
            $path[] = self::NON_WINDOWS_WELL_KNOWN_PATH_BASE;
        }
        $path[] = self::WELL_KNOWN_PATH;
        $path = implode(DIRECTORY_SEPARATOR, $path);
        if (!file_exists($path)) {
            return null;
        }
        $jsonKey = file_get_contents($path);
        return json_decode($jsonKey, true);
    }

    /**
     * @param string $cause
     *
     * @return string
     */
    private static function unableToReadEnv(string $cause): string
    {
        $msg = 'Unable to read the credential file specified by ';
        $msg .= ' GOOGLE_APPLICATION_CREDENTIALS: ';
        $msg .= $cause;

        return $msg;
    }

    /**
     * @return bool
     */
    private static function isOnWindows(): bool
    {
        return strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    }
}
