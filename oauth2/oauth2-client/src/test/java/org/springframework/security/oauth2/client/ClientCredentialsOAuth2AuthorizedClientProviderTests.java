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
package org.springframework.security.oauth2.client;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AccessTokenResponses;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Tests for {@link ClientCredentialsOAuth2AuthorizedClientProvider}.
 *
 * @author Joe Grandja
 */
public class ClientCredentialsOAuth2AuthorizedClientProviderTests {
	private ClientRegistrationRepository clientRegistrationRepository;
	private OAuth2AuthorizedClientRepository authorizedClientRepository;
	private ClientCredentialsOAuth2AuthorizedClientProvider authorizedClientProvider;
	private OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> accessTokenResponseClient;
	private ClientRegistration clientRegistration;
	private Authentication principal;

	@Before
	public void setup() {
		this.clientRegistrationRepository = mock(ClientRegistrationRepository.class);
		this.authorizedClientRepository = mock(OAuth2AuthorizedClientRepository.class);
		this.authorizedClientProvider = new ClientCredentialsOAuth2AuthorizedClientProvider(
				this.clientRegistrationRepository, this.authorizedClientRepository);
		this.accessTokenResponseClient = mock(OAuth2AccessTokenResponseClient.class);
		this.authorizedClientProvider.setAccessTokenResponseClient(this.accessTokenResponseClient);
		this.clientRegistration = TestClientRegistrations.clientCredentials().build();
		this.principal = new TestingAuthenticationToken("principal", "password");
	}

	@Test
	public void constructorWhenClientRegistrationRepositoryIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new ClientCredentialsOAuth2AuthorizedClientProvider(null, this.authorizedClientRepository))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("clientRegistrationRepository cannot be null");
	}

	@Test
	public void constructorWhenOAuth2AuthorizedClientRepositoryIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new ClientCredentialsOAuth2AuthorizedClientProvider(this.clientRegistrationRepository, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizedClientRepository cannot be null");
	}

	@Test
	public void setAccessTokenResponseClientWhenClientIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientProvider.setAccessTokenResponseClient(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("accessTokenResponseClient cannot be null");
	}

	@Test
	public void authorizeWhenContextIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizedClientProvider.authorize(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("context cannot be null");
	}

	@Test
	public void authorizeWhenNotClientCredentialsThenUnableToAuthorize() {
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration().build();
		OAuth2AuthorizationContext authorizationContext =
				OAuth2AuthorizationContext.authorize(clientRegistration).principal(this.principal).build();
		assertThat(this.authorizedClientProvider.authorize(authorizationContext)).isNull();
	}

	@Test
	public void authorizeWhenHttpServletRequestIsNullThenThrowIllegalArgumentException() {
		OAuth2AuthorizationContext authorizationContext =
				OAuth2AuthorizationContext.authorize(this.clientRegistration).principal(this.principal).build();
		assertThatThrownBy(() -> this.authorizedClientProvider.authorize(authorizationContext))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("context.HttpServletRequest cannot be null");
	}

	@Test
	public void authorizeWhenHttpServletResponseIsNullThenThrowIllegalArgumentException() {
		OAuth2AuthorizationContext authorizationContext =
				OAuth2AuthorizationContext.authorize(this.clientRegistration)
						.principal(this.principal)
						.attribute(HttpServletRequest.class.getName(), new MockHttpServletRequest())
						.build();
		assertThatThrownBy(() -> this.authorizedClientProvider.authorize(authorizationContext))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("context.HttpServletResponse cannot be null");
	}

	@Test
	public void authorizeWhenClientCredentialsAndNotAuthorizedThenAuthorize() {
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse().build();
		when(this.accessTokenResponseClient.getTokenResponse(any())).thenReturn(accessTokenResponse);

		OAuth2AuthorizationContext authorizationContext =
				OAuth2AuthorizationContext.authorize(this.clientRegistration)
						.principal(this.principal)
						.attribute(HttpServletRequest.class.getName(), new MockHttpServletRequest())
						.attribute(HttpServletResponse.class.getName(), new MockHttpServletResponse())
						.build();

		OAuth2AuthorizedClient authorizedClient = this.authorizedClientProvider.authorize(authorizationContext);

		assertThat(authorizedClient.getClientRegistration()).isSameAs(this.clientRegistration);
		assertThat(authorizedClient.getPrincipalName()).isEqualTo(this.principal.getName());
		assertThat(authorizedClient.getAccessToken()).isEqualTo(accessTokenResponse.getAccessToken());
		verify(this.authorizedClientRepository).saveAuthorizedClient(
				eq(authorizedClient), eq(this.principal),
				any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void authorizeWhenClientCredentialsAndAuthorizedThenReauthorize() {
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.accessTokenResponse().build();
		when(this.accessTokenResponseClient.getTokenResponse(any())).thenReturn(accessTokenResponse);

		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
				this.clientRegistration, this.principal.getName(), TestOAuth2AccessTokens.noScopes());

		OAuth2AuthorizationContext authorizationContext =
				OAuth2AuthorizationContext.reauthorize(authorizedClient)
						.principal(this.principal)
						.attribute(HttpServletRequest.class.getName(), new MockHttpServletRequest())
						.attribute(HttpServletResponse.class.getName(), new MockHttpServletResponse())
						.build();

		authorizedClient = this.authorizedClientProvider.authorize(authorizationContext);

		assertThat(authorizedClient.getClientRegistration()).isSameAs(this.clientRegistration);
		assertThat(authorizedClient.getPrincipalName()).isEqualTo(this.principal.getName());
		assertThat(authorizedClient.getAccessToken()).isEqualTo(accessTokenResponse.getAccessToken());
		verify(this.authorizedClientRepository).saveAuthorizedClient(
				eq(authorizedClient), eq(this.principal),
				any(HttpServletRequest.class), any(HttpServletResponse.class));
	}
}
