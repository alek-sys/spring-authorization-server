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

import java.security.Principal;
import java.util.Collections;
import java.util.Set;

import org.junit.Test;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import static org.assertj.core.api.AssertionsForInterfaceTypes.assertThat;

/**
 * @author Alexey Nesterov
 */
public class OAuth2TokenRequestTest {

	@Test
	public void builderWhenBuildThenSetResourceOwner() {
		Principal token = new TestingAuthenticationToken("username", "password");
		OAuth2TokenRequest request = OAuth2TokenRequest.builder()
				.resourceOwner(token)
				.build();

		assertThat(request.getResourceOwner()).isEqualTo(token);
	}

	@Test
	public void builderWhenBuildThenSetRegisteredClient() {
		RegisteredClient client = TestRegisteredClients.registeredClient().build();
		OAuth2TokenRequest request = OAuth2TokenRequest.builder()
				.registeredClient(client)
				.build();

		assertThat(request.getRegisteredClient()).isEqualTo(client);
	}

	@Test
	public void builderWhenBuildThenSetScopes() {
		Set<String> expectedScopes = Collections.singleton("test-scope");
		OAuth2TokenRequest request = OAuth2TokenRequest.builder()
				.scopes(expectedScopes)
				.build();

		assertThat(request.getScopes()).isEqualTo(expectedScopes);
	}
}
