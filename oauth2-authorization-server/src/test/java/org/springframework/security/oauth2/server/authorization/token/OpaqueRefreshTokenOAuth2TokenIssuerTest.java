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

import java.time.Instant;

import org.junit.Before;
import org.junit.Test;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

/**
 * @author Alexey Nesterov
 */
public class OpaqueRefreshTokenOAuth2TokenIssuerTest {

	private final Instant now = Instant.now();

	private final RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
	private final TestingAuthenticationToken testResourceOwner = new TestingAuthenticationToken("test", "test");

	private OAuth2TokenIssuer<OAuth2RefreshToken> tokenIssuer;

	@Before
	public void setUp() {
		this.tokenIssuer = new OpaqueRefreshTokenOAuth2TokenIssuer();
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

		AbstractOAuth2Token token = this.tokenIssuer.issue(tokenRequest);
		assertThat(token.getIssuedAt()).isAfter(this.now);
		assertThat(token.getExpiresAt()).isAfter(token.getIssuedAt());
	}

	@Test
	public void issueWhenValidRequestThenReturnUniqueTokenValue() {
		OAuth2TokenRequest tokenRequest = OAuth2TokenRequest.builder()
				.registeredClient(this.registeredClient)
				.resourceOwner(this.testResourceOwner)
				.build();

		AbstractOAuth2Token token1 = this.tokenIssuer.issue(tokenRequest);
		AbstractOAuth2Token token2 = this.tokenIssuer.issue(tokenRequest);

		assertThat(token1.getTokenValue()).isNotEqualTo(token2.getTokenValue());
	}
}
