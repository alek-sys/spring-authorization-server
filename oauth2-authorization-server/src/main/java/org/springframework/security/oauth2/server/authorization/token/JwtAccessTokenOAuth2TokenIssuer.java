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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.springframework.lang.NonNull;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jose.JoseHeader;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.util.Assert;

/**
 * @author Alexey Nesterov
 */
public class JwtAccessTokenOAuth2TokenIssuer implements OAuth2TokenIssuer<OAuth2AccessToken, Jwt> {

	private final JwtEncoder jwtEncoder;
	private final Clock clock;

	private JwtOAuth2TokenCustomizer customizer;
	private Iterable<JwtOAuth2TokenValidator> validators;

	JwtAccessTokenOAuth2TokenIssuer(Clock clock, JwtEncoder jwtEncoder) {
		this.clock = clock;
		this.jwtEncoder = jwtEncoder;
		this.customizer = (header, claims, request) -> {};
		this.validators = getDefaultValidators();
	}

	public void setValidators(Iterable<JwtOAuth2TokenValidator> validators) {
		this.validators = validators;
	}

	private List<JwtOAuth2TokenValidator> getDefaultValidators() {
		return Collections.singletonList(new TokenLifetimeValidator());
	}

	public JwtAccessTokenOAuth2TokenIssuer(JwtEncoder jwtEncoder) {
		this(Clock.systemUTC(), jwtEncoder);
	}

	@Override
	public OAuth2TokenResponse<OAuth2AccessToken, Jwt> issue(@NonNull OAuth2TokenRequest tokenRequest) {
		Assert.notNull(tokenRequest.getResourceOwner(), "resourceOwner cannot be null");
		Assert.notNull(tokenRequest.getRegisteredClient(), "registeredClient cannot be null");

		Instant issuedAt = Instant.now(this.clock);
		Instant expiresAt = issuedAt.plus(Duration.ofHours(1)); // TODO make this configurable

		JoseHeader.Builder joseHeaderBuilder = JoseHeader.withAlgorithm(SignatureAlgorithm.RS256);
		Set<String> scopes = tokenRequest.getScopes();
		JwtClaimsSet.Builder jwtClaimsSetBuilder = JwtClaimsSet.withClaims()
				.subject(tokenRequest.getResourceOwner().getName())
				.audience(Collections.singletonList(tokenRequest.getRegisteredClient().getClientId()))
				.issuedAt(issuedAt)
				.expiresAt(expiresAt)
				.notBefore(issuedAt)
				.claim(OAuth2ParameterNames.SCOPE, scopes);

		this.customizer.customize(joseHeaderBuilder, jwtClaimsSetBuilder, tokenRequest);

		JoseHeader joseHeader = joseHeaderBuilder.build();
		JwtClaimsSet claimsSet = jwtClaimsSetBuilder.build();
		this.validators.forEach(jwtOAuth2TokenValidator -> jwtOAuth2TokenValidator.validate(joseHeader, claimsSet, tokenRequest));

		Jwt jwt = jwtEncoder.encode(joseHeaderBuilder.build(), jwtClaimsSetBuilder.build());
		return OAuth2TokenResponse.with(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, jwt.getTokenValue(), issuedAt, expiresAt, scopes), jwt);
	}

	public void setCustomizer(JwtOAuth2TokenCustomizer customizer) {
		this.customizer = customizer;
	}
}
