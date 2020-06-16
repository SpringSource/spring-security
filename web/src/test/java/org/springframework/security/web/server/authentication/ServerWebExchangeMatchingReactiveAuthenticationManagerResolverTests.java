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

package org.springframework.security.web.server.authentication;

import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.mock;
import static org.springframework.mock.web.server.MockServerWebExchange.from;

/**
 * Tests for {@link ServerWebExchangeMatchingReactiveAuthenticationManagerResolver}
 *
 * @author Josh Cummings
 */
public class ServerWebExchangeMatchingReactiveAuthenticationManagerResolverTests {
	private ReactiveAuthenticationManager one = mock(ReactiveAuthenticationManager.class);
	private ReactiveAuthenticationManager two = mock(ReactiveAuthenticationManager.class);

	@Test
	public void resolveWhenMatchesThenReturnsReactiveAuthenticationManager() {
		List<ServerWebExchangeMatchingReactiveAuthenticationManagerResolver.MatcherEntry> authenticationManagers =
				Arrays.asList(
						new ServerWebExchangeMatchingReactiveAuthenticationManagerResolver.MatcherEntry
								(new PathPatternParserServerWebExchangeMatcher("/one/**"), this.one),
						new ServerWebExchangeMatchingReactiveAuthenticationManagerResolver.MatcherEntry
								(new PathPatternParserServerWebExchangeMatcher("/two/**"), this.two));
		ServerWebExchangeMatchingReactiveAuthenticationManagerResolver resolver =
				new ServerWebExchangeMatchingReactiveAuthenticationManagerResolver(authenticationManagers);

		MockServerHttpRequest request = MockServerHttpRequest.get("/one/location").build();
		assertThat(resolver.resolve(from(request)).block()).isEqualTo(this.one);
	}

	@Test
	public void resolveWhenDoesNotMatchThenReturnsDefaultReactiveAuthenticationManager() {
		List<ServerWebExchangeMatchingReactiveAuthenticationManagerResolver.MatcherEntry> authenticationManagers =
				Arrays.asList(
						new ServerWebExchangeMatchingReactiveAuthenticationManagerResolver.MatcherEntry
								(new PathPatternParserServerWebExchangeMatcher("/one/**"), this.one),
						new ServerWebExchangeMatchingReactiveAuthenticationManagerResolver.MatcherEntry
								(new PathPatternParserServerWebExchangeMatcher("/two/**"), this.two));
		ServerWebExchangeMatchingReactiveAuthenticationManagerResolver resolver =
				new ServerWebExchangeMatchingReactiveAuthenticationManagerResolver(authenticationManagers);

		MockServerHttpRequest request = MockServerHttpRequest.get("/wrong/location").build();
		ReactiveAuthenticationManager authenticationManager =
				resolver.resolve(from(request)).block();

		Authentication authentication = new TestingAuthenticationToken("principal", "creds");
		assertThatCode(() -> authenticationManager.authenticate(authentication).block())
				.isInstanceOf(AuthenticationServiceException.class);
	}
}
