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

package org.springframework.security.saml2.provider.service.web.authentication;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2PostAuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2AuthenticationRequestResolver.Saml2AuthenticationRequestPartial;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

public class Saml2AuthenticationRequestRedirectFilter extends OncePerRequestFilter {

	private final Saml2AuthenticationRequestResolver authenticationRequestResolver;

	public Saml2AuthenticationRequestRedirectFilter(Saml2AuthenticationRequestResolver authenticationRequestResolver) {
		this.authenticationRequestResolver = authenticationRequestResolver;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		Saml2AuthenticationRequestPartial<?> partial = this.authenticationRequestResolver
				.resolveAuthenticationRequest(request);
		if (partial == null) {
			chain.doFilter(request, response);
			return;
		}
		AbstractSaml2AuthenticationRequest authenticationRequest = partial.request();
		if (authenticationRequest instanceof Saml2RedirectAuthenticationRequest) {
			sendRedirect(response, (Saml2RedirectAuthenticationRequest) authenticationRequest);
		}
		else {
			sendPost(response, (Saml2PostAuthenticationRequest) authenticationRequest);
		}
	}

	private void sendRedirect(HttpServletResponse response, Saml2RedirectAuthenticationRequest authenticationRequest)
			throws IOException {
		UriComponentsBuilder uriBuilder = UriComponentsBuilder
				.fromUriString(authenticationRequest.getAuthenticationRequestUri());
		addParameter("SAMLRequest", authenticationRequest.getSamlRequest(), uriBuilder);
		addParameter("RelayState", authenticationRequest.getRelayState(), uriBuilder);
		addParameter("SigAlg", authenticationRequest.getSigAlg(), uriBuilder);
		addParameter("Signature", authenticationRequest.getSignature(), uriBuilder);
		String redirectUrl = uriBuilder.build(true).toUriString();
		response.sendRedirect(redirectUrl);
	}

	private void addParameter(String name, String value, UriComponentsBuilder builder) {
		Assert.hasText(name, "name cannot be empty or null");
		if (StringUtils.hasText(value)) {
			builder.queryParam(UriUtils.encode(name, StandardCharsets.ISO_8859_1),
					UriUtils.encode(value, StandardCharsets.ISO_8859_1));
		}
	}

	private void sendPost(HttpServletResponse response, Saml2PostAuthenticationRequest authenticationRequest)
			throws IOException {
		String html = createSamlPostRequestFormData(authenticationRequest);
		response.setContentType(MediaType.TEXT_HTML_VALUE);
		response.getWriter().write(html);
	}

	private String createSamlPostRequestFormData(Saml2PostAuthenticationRequest authenticationRequest) {
		String authenticationRequestUri = authenticationRequest.getAuthenticationRequestUri();
		String relayState = authenticationRequest.getRelayState();
		String samlRequest = authenticationRequest.getSamlRequest();
		StringBuilder html = new StringBuilder();
		html.append("<!DOCTYPE html>\n");
		html.append("<html>\n").append("    <head>\n");
		html.append("        <meta charset=\"utf-8\" />\n");
		html.append("    </head>\n");
		html.append("    <body onload=\"document.forms[0].submit()\">\n");
		html.append("        <noscript>\n");
		html.append("            <p>\n");
		html.append("                <strong>Note:</strong> Since your browser does not support JavaScript,\n");
		html.append("                you must press the Continue button once to proceed.\n");
		html.append("            </p>\n");
		html.append("        </noscript>\n");
		html.append("        \n");
		html.append("        <form action=\"");
		html.append(authenticationRequestUri);
		html.append("\" method=\"post\">\n");
		html.append("            <div>\n");
		html.append("                <input type=\"hidden\" name=\"SAMLRequest\" value=\"");
		html.append(HtmlUtils.htmlEscape(samlRequest));
		html.append("\"/>\n");
		if (StringUtils.hasText(relayState)) {
			html.append("                <input type=\"hidden\" name=\"RelayState\" value=\"");
			html.append(HtmlUtils.htmlEscape(relayState));
			html.append("\"/>\n");
		}
		html.append("            </div>\n");
		html.append("            <noscript>\n");
		html.append("                <div>\n");
		html.append("                    <input type=\"submit\" value=\"Continue\"/>\n");
		html.append("                </div>\n");
		html.append("            </noscript>\n");
		html.append("        </form>\n");
		html.append("        \n");
		html.append("    </body>\n");
		html.append("</html>");
		return html.toString();
	}

}
