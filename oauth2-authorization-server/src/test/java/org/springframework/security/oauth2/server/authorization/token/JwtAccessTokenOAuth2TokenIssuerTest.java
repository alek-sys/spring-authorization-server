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

import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Set;

import com.nimbusds.jose.shaded.json.JSONArray;
import org.junit.Before;
import org.junit.Test;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.crypto.keys.StaticKeyGeneratingKeyManager;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jose.jws.NimbusJwsEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForInterfaceTypes.assertThat;

/**
 * @author Alexey Nesterov
 */
public class JwtAccessTokenOAuth2TokenIssuerTest {

	private final RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
	private final TestingAuthenticationToken testResourceOwner = new TestingAuthenticationToken("test", "test");
	private final Instant now = Instant.now();

	private JwtEncoder jwtEncoder;
	private JwtDecoder jwtDecoder;
	private JwtAccessTokenOAuth2TokenIssuer tokenIssuer;

	@Before
	public void setUp() {
		StaticKeyGeneratingKeyManager keyManager = new StaticKeyGeneratingKeyManager();
		RSAPublicKey publicKey = (RSAPublicKey) keyManager.findByAlgorithm("RSA").iterator().next().getPublicKey();

		this.jwtEncoder = new NimbusJwsEncoder(keyManager);
		this.jwtDecoder = NimbusJwtDecoder.withPublicKey(publicKey).build();
		this.tokenIssuer = new JwtAccessTokenOAuth2TokenIssuer(Clock.fixed(this.now, ZoneId.of("UTC")), this.jwtEncoder);
	}

	@Test
	public void issueWhenNoResourceOwnerThenThrowException() {
		OAuth2TokenRequest tokenRequest = OAuth2TokenRequest.builder()
				.registeredClient(this.registeredClient)
				.build();

		assertThatThrownBy(() -> this.tokenIssuer.issue(tokenRequest))
				.isInstanceOf(IllegalArgumentException.class)
				.extracting(Throwable::getMessage)
				.isEqualTo("resourceOwner cannot be null");
	}

	@Test
	public void issueWhenNoRegisteredClientThenThrowException() {
		OAuth2TokenRequest tokenRequest = OAuth2TokenRequest.builder()
				.resourceOwner(this.testResourceOwner)
				.build();

		assertThatThrownBy(() -> this.tokenIssuer.issue(tokenRequest))
				.isInstanceOf(IllegalArgumentException.class)
				.extracting(Throwable::getMessage)
				.isEqualTo("registeredClient cannot be null");
	}

	@Test
	public void issueWhenValidRequestThenSetTokenLifetime() {
		OAuth2TokenRequest tokenRequest = OAuth2TokenRequest.builder()
				.registeredClient(this.registeredClient)
				.resourceOwner(this.testResourceOwner)
				.build();

		OAuth2AccessToken accessToken = this.tokenIssuer.issue(tokenRequest);
		assertThat(accessToken.getIssuedAt()).isEqualTo(this.now);
		assertThat(accessToken.getExpiresAt()).isAfter(this.now);
	}

	@Test
	public void issueWhenValidRequestThenSetScopes() {
		Set<String> expectedScopes = Collections.singleton("test-scope");
		OAuth2TokenRequest tokenRequest = OAuth2TokenRequest.builder()
				.registeredClient(this.registeredClient)
				.resourceOwner(this.testResourceOwner)
				.scopes(expectedScopes)
				.build();

		OAuth2AccessToken accessToken = this.tokenIssuer.issue(tokenRequest);
		Jwt decodedJwt = decode(accessToken.getTokenValue());

		JSONArray actualScopes = decodedJwt.getClaim("scope");
		assertThat(actualScopes).containsAll(expectedScopes);
		assertThat(accessToken.getScopes()).containsAll(expectedScopes);
	}

	@Test
	public void issueWhenValidRequestThenSetOAuth2Claims() {
		Set<String> expectedScopes = Collections.singleton("test-scope");
		OAuth2TokenRequest tokenRequest = OAuth2TokenRequest.builder()
				.registeredClient(this.registeredClient)
				.resourceOwner(this.testResourceOwner)
				.scopes(expectedScopes)
				.build();

		OAuth2AccessToken accessToken = this.tokenIssuer.issue(tokenRequest);
		Jwt decodedJwt = decode(accessToken.getTokenValue());

		assertThat(decodedJwt.getClaims())
				.containsEntry("sub", this.testResourceOwner.getPrincipal())
				.containsEntry("aud", Collections.singletonList(this.registeredClient.getClientId()))
				.containsEntry("iat", this.now.truncatedTo(ChronoUnit.SECONDS))
				.containsEntry("nbf", this.now.truncatedTo(ChronoUnit.SECONDS));
	}

	@Test
	public void issueWhenCustomizerProvidedThenTokenCustomized() {
		final OAuth2TokenRequest tokenRequest = OAuth2TokenRequest.builder()
				.registeredClient(this.registeredClient)
				.resourceOwner(this.testResourceOwner)
				.build();

		this.tokenIssuer.setCustomizer((joseHeaderBuilder, jwtClaimsSetBuilder, request) -> {
			joseHeaderBuilder.header("new-header", "header-value");
			jwtClaimsSetBuilder.claim("new-claim", "claim-value");

			assertThat(request).isEqualTo(tokenRequest);
		});

		OAuth2AccessToken accessToken = this.tokenIssuer.issue(tokenRequest);
		Jwt decodedJwt = decode(accessToken.getTokenValue());

		assertThat(decodedJwt.getHeaders()).containsEntry("new-header", "header-value");
		assertThat(decodedJwt.getClaims()).containsEntry("new-claim", "claim-value");
	}

	@Test
	public void issueWhenNoValidatorsSetThenConfiguresDefaultValidators() {
		final OAuth2TokenRequest tokenRequest = OAuth2TokenRequest.builder()
				.registeredClient(this.registeredClient)
				.resourceOwner(this.testResourceOwner)
				.build();

		this.tokenIssuer.setCustomizer((joseHeaderBuilder, jwtClaimsSetBuilder, request) -> {
			jwtClaimsSetBuilder.issuedAt(Instant.now());
			jwtClaimsSetBuilder.expiresAt(Instant.now().minusSeconds(10));
		});

		assertThatThrownBy(() -> this.tokenIssuer.issue(tokenRequest))
				.isInstanceOf(IllegalStateException.class)
				.extracting(Throwable::getMessage)
				.isEqualTo("expiresAt cannot be before issuedAt");
	}

	@Test
	public void issueWhenValidatorsSetThenCallsValidators() {
		final OAuth2TokenRequest tokenRequest = OAuth2TokenRequest.builder()
				.registeredClient(this.registeredClient)
				.resourceOwner(this.testResourceOwner)
				.build();

		this.tokenIssuer.setCustomizer((joseHeaderBuilder, jwtClaimsSetBuilder, request) -> {
			joseHeaderBuilder.header("new-header", "header-value");
			jwtClaimsSetBuilder.claim("new-claim", "claim-value");
		});

		this.tokenIssuer.setValidators(Collections.singletonList((joseHeader, claimsSet, request) -> {
			assertThat(request).isEqualTo(tokenRequest);
			assertThat(joseHeader.getHeaders()).containsEntry("new-header", "header-value");
			assertThat(claimsSet.getClaims()).containsEntry("new-claim", "claim-value");
		}));

		this.tokenIssuer.issue(tokenRequest);
	}

	private Jwt decode(String tokenValue) {
		return this.jwtDecoder.decode(tokenValue);
	}
}
