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

/**
 * Authenticates requests using Google's Service Account credentials via
 * JWT Access.
 *
 * This class allows authorizing requests for service accounts directly
 * from credentials from a json key file downloaded from the developer
 * console (via 'Generate new Json Key').  It is not part of any OAuth2
 * flow, rather it creates a JWT and sends that as a credential.
 */
class ServiceAccountJwtAccessCredentials implements
    CredentialsInterface,
    SignBlobInterface
{
    use CredentialsTrait;
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
     */
    private $quotaProject;

    /**
     * Create a new ServiceAccountJwtAccessCredentials.
     *
     * @param string $audience the audience for the JWT
     * @param string|array $jsonKey JSON credential file path or JSON credentials
     *   as an associative array
     */
    public function __construct($jsonKey, string $audience, array $options = [])
    {
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
        if (array_key_exists('quota_project_id', $jsonKey)) {
            $this->quotaProject = (string) $jsonKey['quota_project_id'];
        }

        $this->setHttpClientFromOptions($options);

        $this->oauth2 = new OAuth2([
            'issuer' => $jsonKey['client_email'],
            'sub' => $jsonKey['client_email'],
            'signingAlgorithm' => 'RS256',
            'signingKey' => $jsonKey['private_key'],
            'audience' => $audience,
            'httpClient' => $this->httpClient,
        ]);

        $this->projectId = isset($jsonKey['project_id'])
            ? $jsonKey['project_id']
            : null;
    }

    /**
     * Implements FetchAuthTokenInterface#fetchAuthToken.
     *
     * @return array A set of auth related metadata, containing the
     * following keys:
     *   - access_token (string)
     */
    public function fetchAuthToken(): array
    {
        $access_token = $this->oauth2->toJwt();

        return ['access_token' => $access_token];
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
     * Get the quota project used for this API request
     *
     * @return string|null
     */
    public function getQuotaProject(): ?string
    {
        return $this->quotaProject;
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

    /**
     * @return string
     */
    private function getCacheKey()
    {
        return $this->oauth2->getCacheKey();
    }
}
