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

/**
 * @author Alexey Nesterov
 */
public class OAuth2TokenResponse<TOKEN_TYPE, TOKEN_IDENTITY_TYPE> {

	private final TOKEN_TYPE token;
	private final TOKEN_IDENTITY_TYPE identity;

	private OAuth2TokenResponse(TOKEN_TYPE token, TOKEN_IDENTITY_TYPE identity) {
		this.token = token;
		this.identity = identity;
	}

	public static <TOKEN_TYPE, TOKEN_IDENTITY_TYPE> OAuth2TokenResponse<TOKEN_TYPE, TOKEN_IDENTITY_TYPE> with(TOKEN_TYPE token, TOKEN_IDENTITY_TYPE tokenIdentity) {
		return new OAuth2TokenResponse<>(token, tokenIdentity);
	}

	public TOKEN_TYPE getToken() {
		return token;
	}

	public TOKEN_IDENTITY_TYPE getIdentity() {
		return identity;
	}
}
