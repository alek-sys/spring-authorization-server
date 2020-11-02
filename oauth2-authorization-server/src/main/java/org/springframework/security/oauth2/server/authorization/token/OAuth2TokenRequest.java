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

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

/**
 * @author Alexey Nesterov
 */
public class OAuth2TokenRequest {

	private final Principal resourceOwner;
	private final RegisteredClient registeredClient;
	private final Set<String> scopes;

	private OAuth2TokenRequest(Principal resourceOwner, RegisteredClient registeredClient, Set<String> scopes) {
		this.resourceOwner = resourceOwner;
		this.registeredClient = registeredClient;
		this.scopes = scopes;
	}

	public RegisteredClient getRegisteredClient() {
		return this.registeredClient;
	}

	public Principal getResourceOwner() {
		return this.resourceOwner;
	}

	public Set<String> getScopes() {
		return scopes;
	}

	public static OAuth2TokenRequestBuilder builder() {
		return new OAuth2TokenRequestBuilder();
	}

	public static class OAuth2TokenRequestBuilder {

		private RegisteredClient registeredClient;
		private Principal resourceOwner;
		private Set<String> scopes = Collections.emptySet();

		private OAuth2TokenRequestBuilder() {

		}

		public OAuth2TokenRequestBuilder registeredClient(RegisteredClient client) {
			this.registeredClient = client;
			return this;
		}

		public OAuth2TokenRequestBuilder resourceOwner(Principal resourceOwnerPrincipal) {
			this.resourceOwner = resourceOwnerPrincipal;
			return this;
		}

		public OAuth2TokenRequestBuilder scopes(Set<String> scopes) {
			this.scopes = scopes;
			return this;
		}

		public OAuth2TokenRequest build() {
			return new OAuth2TokenRequest(this.resourceOwner, this.registeredClient, this.scopes);
		}
	}
}
