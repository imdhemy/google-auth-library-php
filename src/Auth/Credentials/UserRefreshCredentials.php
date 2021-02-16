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

use Google\Auth\OAuth2;

/**
 * Authenticates requests using User Refresh credentials.
 *
 * This class allows authorizing requests from user refresh tokens.
 *
 * This the end of the result of a 3LO flow using the `gcloud` CLI.
 * 'gcloud auth login' saves a file with these contents in well known
 * location.
 *
 * @see [Application Default Credentials](http://goo.gl/mkAHpZ)
 */
class UserRefreshCredentials implements CredentialsInterface
{
    use CredentialsTrait;

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
     * Create a new UserRefreshCredentials.
     *
     * @param array $jsonKey JSON credential as an associative array
     * @param string|array $scope the scope of the access request, expressed
     *   either as an Array or as a space-delimited String.
     */
    public function __construct($jsonKey, array $options = [])
    {
        $options += [
            'scope' => null,
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

        if (!array_key_exists('client_id', $jsonKey)) {
            throw new \InvalidArgumentException(
                'json key is missing the client_id field'
            );
        }
        if (!array_key_exists('client_secret', $jsonKey)) {
            throw new \InvalidArgumentException(
                'json key is missing the client_secret field'
            );
        }
        if (!array_key_exists('refresh_token', $jsonKey)) {
            throw new \InvalidArgumentException(
                'json key is missing the refresh_token field'
            );
        }

        $this->setHttpClientFromOptions($options);
        $this->setCacheFromOptions($options);

        $this->oauth2 = new OAuth2([
            'clientId' => $jsonKey['client_id'],
            'clientSecret' => $jsonKey['client_secret'],
            'refreshToken' => $jsonKey['refresh_token'],
            'scope' => $options['scope'] ?? null,
            'httpClient' => $this->httpClient,
            'tokenCredentialUri' => self::TOKEN_CREDENTIAL_URI,
        ]);
        if (array_key_exists('quota_project_id', $jsonKey)) {
            $this->quotaProject = (string) $jsonKey['quota_project_id'];
        }
    }

    /**
     * @return array A set of auth related metadata, containing the following
     * keys:
     *   - access_token (string)
     *   - expires_in (int)
     *   - scope (string)
     *   - token_type (string)
     *   - id_token (string)
     */
    public function fetchAuthToken(): array
    {
        return $this->oauth2->fetchAuthToken();
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
     * Get the project ID.
     *
     * @return string|null
     */
    public function getProjectId(): ?string
    {
        throw new \RuntimeException(
            'getProjectId is not implemented for user refresh credentials'
        );
    }

    /**
     * @return string
     */
    private function getCacheKey(): string
    {
        return $this->oauth2->getClientId() . ':' . $this->oauth2->getCacheKey();
    }
}
