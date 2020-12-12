/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.saml2.provider.service.web.authentication.logout;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestResolver.Saml2LogoutRequestPartial;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

/**
 * A filter for initiating logout with a SAML 2.0 Asserting Party.
 *
 * Note that logout does not complete until the application receives a SAML 2.0 Logout
 * Response from the asserting party.
 *
 * @author Josh Cummings
 * @since 5.5
 */
public final class Saml2RelyingPartyInitiatedLogoutFilter extends OncePerRequestFilter {

	private RequestMatcher logoutRequestMatcher = new AntPathRequestMatcher("/saml2/logout", "POST");

	private final Saml2LogoutRequestResolver logoutRequestResolver;

	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	/**
	 * Constructs a {@link Saml2RelyingPartyInitiatedLogoutFilter} with the provided
	 * parameters
	 * @param logoutRequestResolver the {@link Saml2LogoutRequestResolver} to use
	 */
	public Saml2RelyingPartyInitiatedLogoutFilter(Saml2LogoutRequestResolver logoutRequestResolver) {
		Assert.notNull(logoutRequestResolver, "logoutRequestResolver cannot be null");
		this.logoutRequestResolver = logoutRequestResolver;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		if (!this.logoutRequestMatcher.matches(request)) {
			chain.doFilter(request, response);
			return;
		}
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null) {
			chain.doFilter(request, response);
			return;
		}
		Saml2LogoutRequestPartial<?> partial = this.logoutRequestResolver.resolveLogoutRequest(request, authentication);
		if (partial == null) {
			chain.doFilter(request, response);
			return;
		}
		Saml2LogoutRequest logoutRequest = partial.logoutRequest();
		Saml2MessageBinding binding = logoutRequest.getBinding();
		// redirect to asserting party
		if (binding == Saml2MessageBinding.REDIRECT) {
			doRedirect(request, response, logoutRequest);
		}
		else {
			doPost(response, logoutRequest);
		}

	}

	private void doRedirect(HttpServletRequest request, HttpServletResponse response, Saml2LogoutRequest logoutRequest)
			throws IOException {
		String location = logoutRequest.getLocation();
		UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(location);
		addParameter("SAMLRequest", logoutRequest, uriBuilder);
		addParameter("SigAlg", logoutRequest, uriBuilder);
		addParameter("Signature", logoutRequest, uriBuilder);
		this.redirectStrategy.sendRedirect(request, response, uriBuilder.build(true).toUriString());
	}

	private void addParameter(String name, Saml2LogoutRequest logoutRequest, UriComponentsBuilder builder) {
		Assert.hasText(name, "name cannot be empty or null");
		if (StringUtils.hasText(logoutRequest.getParameter(name))) {
			builder.queryParam(UriUtils.encode(name, StandardCharsets.ISO_8859_1),
					UriUtils.encode(logoutRequest.getParameter(name), StandardCharsets.ISO_8859_1));
		}
	}

	private void doPost(HttpServletResponse response, Saml2LogoutRequest logoutRequest) throws IOException {
		String html = createSamlPostRequestFormData(logoutRequest);
		response.setContentType(MediaType.TEXT_HTML_VALUE);
		response.getWriter().write(html);
	}

	private String createSamlPostRequestFormData(Saml2LogoutRequest logoutRequest) {
		String location = logoutRequest.getLocation();
		String samlRequest = logoutRequest.getSamlRequest();
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
		html.append(location);
		html.append("\" method=\"post\">\n");
		html.append("            <div>\n");
		html.append("                <input type=\"hidden\" name=\"SAMLRequest\" value=\"");
		html.append(HtmlUtils.htmlEscape(samlRequest));
		html.append("\"/>\n");
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
