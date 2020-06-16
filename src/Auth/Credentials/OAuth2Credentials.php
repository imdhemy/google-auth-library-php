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
 * Provides a set of credentials that will always return an empty access token.
 * This is useful for APIs which do not require authentication, for local
 * service emulators, and for testing.
 */
class OAuth2Credentials implements CredentialsInterface
{
    use CredentialsTrait;

    /**
     * @var \Google\Auth\OAuth2
     */
    private $oauth2;

    public function __construct(OAuth2 $oauth2)
    {
        $this->oauth2 = $oauth2;
    }

    /**
     * Fetches the auth tokens based on the current state.
     *
     * @return array a hash of auth tokens
     */
    public function fetchAuthToken(): array
    {
        return $this->oauth2->fetchAuthToken();
    }

    /**
     * Get the project ID.
     *
     * @return string|null
     */
    public function getProjectId(): ?string
    {
        throw new \Exception(
            'getProjectId is not implemented for OAuth2 credentials'
        );
    }

    /**
     * Get the quota project used for this API request
     *
     * @return string|null
     */
    public function getQuotaProject(): ?string
    {
        throw new \Exception(
            'getQuotaProject is not implemented for OAuth2 credentials'
        );
    }
}
