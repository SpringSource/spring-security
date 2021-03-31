/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.oauth2.client.endpoint;

import java.net.URI;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * A {@link Converter} that converts the provided
 * {@link OAuth2ClientCredentialsGrantRequest} to a {@link RequestEntity} representation
 * of an OAuth 2.0 Access Token Request for the Client Credentials Grant.
 *
 * @author Joe Grandja
 * @since 5.1
 * @see OAuth2AuthorizationGrantRequestEntityConverter
 * @see OAuth2ClientCredentialsGrantRequest
 * @see RequestEntity
 */
public class OAuth2ClientCredentialsGrantRequestEntityConverter
		implements OAuth2AuthorizationGrantRequestEntityConverter<OAuth2ClientCredentialsGrantRequest> {

	private Customizer<OAuth2ClientCredentialsGrantRequest> customizer = (request, headers, parameters) -> {
	};

	/**
	 * Returns the {@link RequestEntity} used for the Access Token Request.
	 * @param clientCredentialsGrantRequest the client credentials grant request
	 * @return the {@link RequestEntity} used for the Access Token Request
	 */
	@Override
	public RequestEntity<?> convert(OAuth2ClientCredentialsGrantRequest clientCredentialsGrantRequest) {
		ClientRegistration clientRegistration = clientCredentialsGrantRequest.getClientRegistration();
		HttpHeaders headers = OAuth2AuthorizationGrantRequestEntityUtils.getTokenRequestHeaders(clientRegistration);
		MultiValueMap<String, String> parameters = createParameters(clientCredentialsGrantRequest);
		this.customizer.customize(clientCredentialsGrantRequest, headers, parameters);
		URI uri = UriComponentsBuilder.fromUriString(clientRegistration.getProviderDetails().getTokenUri()).build()
				.toUri();
		return new RequestEntity<>(parameters, headers, HttpMethod.POST, uri);
	}

	/**
	 * Sets the {@link Customizer} to be provided the opportunity to customize the
	 * {@link HttpHeaders headers} and/or {@link MultiValueMap parameters} of the OAuth
	 * 2.0 Access Token Request.
	 * @param customizer the {@link Customizer} to be provided the opportunity to
	 * customize the OAuth 2.0 Access Token Request
	 * @since 5.5
	 */
	public final void setCustomizer(Customizer<OAuth2ClientCredentialsGrantRequest> customizer) {
		Assert.notNull(customizer, "customizer cannot be null");
		this.customizer = customizer;
	}

	/**
	 * Returns a {@link MultiValueMap} of the form parameters used for the Access Token
	 * Request body.
	 * @param clientCredentialsGrantRequest the client credentials grant request
	 * @return a {@link MultiValueMap} of the form parameters used for the Access Token
	 * Request body
	 */
	private MultiValueMap<String, String> createParameters(
			OAuth2ClientCredentialsGrantRequest clientCredentialsGrantRequest) {
		ClientRegistration clientRegistration = clientCredentialsGrantRequest.getClientRegistration();
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.add(OAuth2ParameterNames.GRANT_TYPE, clientCredentialsGrantRequest.getGrantType().getValue());
		if (!CollectionUtils.isEmpty(clientRegistration.getScopes())) {
			parameters.add(OAuth2ParameterNames.SCOPE,
					StringUtils.collectionToDelimitedString(clientRegistration.getScopes(), " "));
		}
		if (ClientAuthenticationMethod.CLIENT_SECRET_POST.equals(clientRegistration.getClientAuthenticationMethod())
				|| ClientAuthenticationMethod.POST.equals(clientRegistration.getClientAuthenticationMethod())) {
			parameters.add(OAuth2ParameterNames.CLIENT_ID, clientRegistration.getClientId());
			parameters.add(OAuth2ParameterNames.CLIENT_SECRET, clientRegistration.getClientSecret());
		}
		return parameters;
	}

}
