/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.server.resource.authentication;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.ScopeClaimAccessor;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * @author Rob Winch
 * @since 5.1
 */
class JwtConverter {
	private static final String SCOPE_AUTHORITY_PREFIX = "SCOPE_";

	private static final Collection<String> WELL_KNOWN_SCOPE_ATTRIBUTE_NAMES =
			Arrays.asList("scope", "scp");


	JwtAuthenticationToken convert(Jwt jwt) {
		Collection<GrantedAuthority> authorities =
				this.getScopes(jwt)
						.stream()
						.map(authority -> SCOPE_AUTHORITY_PREFIX + authority)
						.map(SimpleGrantedAuthority::new)
						.collect(Collectors.toList());

		return new JwtAuthenticationToken(jwt, authorities);
	}

	private Collection<String> getScopes(Jwt jwt) {
		ScopeClaimAccessor claimAccessor = () -> jwt.getClaims();
		for ( String attributeName : WELL_KNOWN_SCOPE_ATTRIBUTE_NAMES ) {
			Collection<String> scopes = claimAccessor.getScope(attributeName);
			if (scopes != null) {
				return scopes;
			}
		}

		return Collections.emptyList();
	}
}
