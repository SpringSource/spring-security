/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.web.authentication;

import java.util.LinkedHashMap;

import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link RequestMatchingAuthenticationManagerResolverTests}
 *
 * @author Josh Cummings
 */
public class RequestMatchingAuthenticationManagerResolverTests {
	private AuthenticationManager one = mock(AuthenticationManager.class);
	private AuthenticationManager two = mock(AuthenticationManager.class);

	@Test
	public void resolveWhenMatchesThenReturnsAuthenticationManager() {
		LinkedHashMap<RequestMatcher, AuthenticationManager> authenticationManagers = new LinkedHashMap<>();
		authenticationManagers.put(new AntPathRequestMatcher("/one/**"), this.one);
		authenticationManagers.put(new AntPathRequestMatcher("/two/**"), this.two);
		RequestMatchingAuthenticationManagerResolver resolver =
				new RequestMatchingAuthenticationManagerResolver(authenticationManagers);

		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/one/location");
		request.setServletPath("/one/location");
		assertThat(resolver.resolve(request)).isEqualTo(this.one);
	}

	@Test
	public void resolveWhenDoesNotMatchThenReturnsDefaultAuthenticationManager() {
		LinkedHashMap<RequestMatcher, AuthenticationManager> authenticationManagers = new LinkedHashMap<>();
		authenticationManagers.put(new AntPathRequestMatcher("/one/**"), this.one);
		authenticationManagers.put(new AntPathRequestMatcher("/two/**"), this.two);
		RequestMatchingAuthenticationManagerResolver resolver =
				new RequestMatchingAuthenticationManagerResolver(authenticationManagers);

		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/wrong/location");
		AuthenticationManager authenticationManager = resolver.resolve(request);

		Authentication authentication = new TestingAuthenticationToken("principal", "creds");
		assertThatCode(() -> authenticationManager.authenticate(authentication))
				.isInstanceOf(AuthenticationServiceException.class);
	}
}
