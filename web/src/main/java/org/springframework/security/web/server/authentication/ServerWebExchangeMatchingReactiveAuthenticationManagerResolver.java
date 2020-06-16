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

import java.util.List;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;

/**
 * A {@link ReactiveAuthenticationManagerResolver} that returns a {@link ReactiveAuthenticationManager}
 * instances based upon the type of {@link ServerWebExchange} passed into
 * {@link #resolve(ServerWebExchange)}.
 *
 * @author Josh Cummings
 * @since 5.2
 *
 */
public class ServerWebExchangeMatchingReactiveAuthenticationManagerResolver
		implements ReactiveAuthenticationManagerResolver<ServerWebExchange> {

	private final List<MatcherEntry> authenticationManagers;
	private ReactiveAuthenticationManager defaultAuthenticationManager = authentication ->
		Mono.error(new AuthenticationServiceException("Cannot authenticate " + authentication));

	/**
	 * Construct an {@link ServerWebExchangeMatchingReactiveAuthenticationManagerResolver}
	 * based on the provided parameters
	 *
	 * @param authenticationManagers a {@link List} of
	 * {@link ServerWebExchangeMatcher}/{@link ReactiveAuthenticationManager} pairs
	 */
	public ServerWebExchangeMatchingReactiveAuthenticationManagerResolver
			(List<MatcherEntry> authenticationManagers) {

		Assert.notNull(authenticationManagers, "authenticationManagers cannot be null");
		this.authenticationManagers = authenticationManagers;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Mono<ReactiveAuthenticationManager> resolve(ServerWebExchange exchange) {
		return Flux.fromIterable(this.authenticationManagers)
				.filterWhen(entry -> isMatch(exchange, entry))
				.next()
				.map(MatcherEntry::getAuthenticationManager)
				.defaultIfEmpty(this.defaultAuthenticationManager);
	}

	/**
	 * Set the default {@link ReactiveAuthenticationManager} to use when a request does not match
	 *
	 * @param defaultAuthenticationManager the default {@link ReactiveAuthenticationManager} to use
	 */
	public void setDefaultAuthenticationManager(ReactiveAuthenticationManager defaultAuthenticationManager) {
		Assert.notNull(defaultAuthenticationManager, "defaultAuthenticationManager cannot be null");
		this.defaultAuthenticationManager = defaultAuthenticationManager;
	}

	public static class MatcherEntry {
		private final ServerWebExchangeMatcher matcher;
		private final ReactiveAuthenticationManager authenticationManager;

		public MatcherEntry(ServerWebExchangeMatcher matcher,
				ReactiveAuthenticationManager authenticationManager) {
			this.matcher = matcher;
			this.authenticationManager = authenticationManager;
		}

		public ServerWebExchangeMatcher getMatcher() {
			return this.matcher;
		}

		public ReactiveAuthenticationManager getAuthenticationManager() {
			return this.authenticationManager;
		}
	}

	private Mono<Boolean> isMatch(ServerWebExchange exchange, MatcherEntry entry) {
		ServerWebExchangeMatcher matcher = entry.getMatcher();
		return matcher.matches(exchange)
				.map(ServerWebExchangeMatcher.MatchResult::isMatch);
	}
}
