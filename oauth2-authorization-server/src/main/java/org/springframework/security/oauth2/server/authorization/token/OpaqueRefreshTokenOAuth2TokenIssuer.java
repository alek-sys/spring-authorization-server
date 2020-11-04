/*
 * Copyright 2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.server.authorization.token;

import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.util.Assert;

/**
 * @author Alexey Nesterov
 */
public class OpaqueRefreshTokenOAuth2TokenIssuer implements OAuth2TokenIssuer<OAuth2RefreshToken, String> {

	private final StringKeyGenerator keyGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);

	@Override
	public OAuth2TokenResponse<OAuth2RefreshToken, String> issue(OAuth2TokenRequest tokenRequest) {
		Assert.notNull(tokenRequest.getRegisteredClient(), "registeredClient cannot be null");
		Assert.notNull(tokenRequest.getResourceOwner(), "resourceOwner cannot be null");
		Assert.notNull(tokenRequest.getScopes(), "scopes cannot be null");

		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(Duration.ofMinutes(60));
		String tokenValue = this.keyGenerator.generateKey();
		return OAuth2TokenResponse.with(new OAuth2RefreshToken(tokenValue, issuedAt, expiresAt), tokenValue);
	}
}
