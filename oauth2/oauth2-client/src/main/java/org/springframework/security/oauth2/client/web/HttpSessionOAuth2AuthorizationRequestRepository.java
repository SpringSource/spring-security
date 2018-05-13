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
package org.springframework.security.oauth2.client.web;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.Map;

/**
 * An implementation of an {@link AuthorizationRequestRepository} that stores
 * {@link OAuth2AuthorizationRequest} in the {@code HttpSession}.
 *
 * @author Joe Grandja
 * @author Rob Winch
 * @since 5.0
 * @see AuthorizationRequestRepository
 * @see OAuth2AuthorizationRequest
 */
public final class HttpSessionOAuth2AuthorizationRequestRepository implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {
	private static final String DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME =
			HttpSessionOAuth2AuthorizationRequestRepository.class.getName() +  ".AUTHORIZATION_REQUEST";

	private final String sessionAttributeName = DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME;

	@Override
	public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request,
											HttpServletResponse response, ClientRegistration clientRegistration) {
		Assert.notNull(request, "request cannot be null");
		Assert.notNull(response, "response cannot be null");
		Assert.notNull(clientRegistration, "clientRegistration cannot be null");
		if (authorizationRequest == null) {
			this.removeAuthorizationRequest(request, clientRegistration);
			return;
		}
		String state = authorizationRequest.getState();
		Assert.hasText(state, "authorizationRequest.state cannot be empty");
		Map<String, OAuth2AuthorizationRequest> authorizationRequests = this.getAuthorizationRequests(request);
		authorizationRequests.put(state, authorizationRequest);
		request.getSession().setAttribute(this.sessionAttributeName, authorizationRequests);
	}

	@Override
	public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request, ClientRegistration clientRegistration) {
		Assert.notNull(request, "request cannot be null");
		Assert.notNull(clientRegistration, "clientRegistration cannot be null");
		String stateParameter = this.getStateParameter(request, clientRegistration);
		if (stateParameter == null) {
			return null;
		}
		Map<String, OAuth2AuthorizationRequest> authorizationRequests = this.getAuthorizationRequests(request);
		OAuth2AuthorizationRequest originalRequest = authorizationRequests.remove(stateParameter);
		request.getSession().setAttribute(this.sessionAttributeName, authorizationRequests);
		return originalRequest;
	}

	/**
	 * Gets the state parameter from the {@link HttpServletRequest}
	 * @param request the request to use
	 * @param clientRegistration the {@code ClientRegistration}
	 * @return the state parameter or null if not found
	 */
	private String getStateParameter(HttpServletRequest request, ClientRegistration clientRegistration) {
		return request.getParameter(clientRegistration.getProviderDetails().getStateAttributeName());
	}

	/**
	 * Gets a non-null and mutable map of {@link OAuth2AuthorizationRequest#getState()} to an {@link OAuth2AuthorizationRequest}
	 * @param request
	 * @return a non-null and mutable map of {@link OAuth2AuthorizationRequest#getState()} to an {@link OAuth2AuthorizationRequest}.
	 */
	private Map<String, OAuth2AuthorizationRequest> getAuthorizationRequests(HttpServletRequest request) {
		HttpSession session = request.getSession(false);
		Map<String, OAuth2AuthorizationRequest> authorizationRequests = session == null ? null :
				(Map<String, OAuth2AuthorizationRequest>) session.getAttribute(this.sessionAttributeName);
		if (authorizationRequests == null) {
			return new HashMap<>();
		}
		return authorizationRequests;
	}
}
