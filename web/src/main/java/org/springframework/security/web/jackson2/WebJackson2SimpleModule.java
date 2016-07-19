/*
 * Copyright 2015-2016 the original author or authors.
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

package org.springframework.security.web.jackson2;

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.module.SimpleModule;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;

import javax.servlet.http.Cookie;

/**
 * Jackson module for spring-security-web. This module register {@link CookieMixin},
 * {@link DefaultCsrfTokenMixin}, {@link DefaultSavedRequestMixin} and {@link WebAuthenticationDetailsMixin}.
 * In order to use this module just add this module into your ObjectMapper configuration.
 *
 * <pre>
 *     ObjectMapper mapper = new ObjectMapper();
 *     mapper.registerModule(new WebJackson2SimpleModule());
 * </pre>
 *
 * @author Jitendra Singh
 * @since 4.2
 */
public class WebJackson2SimpleModule extends SimpleModule {

	public WebJackson2SimpleModule() {
		super(WebJackson2SimpleModule.class.getName(), new Version(1, 0, 0, null, null, null));
	}

	@Override
	public void setupModule(SetupContext context) {
		context.setMixInAnnotations(Cookie.class, CookieMixin.class);
		context.setMixInAnnotations(DefaultCsrfToken.class, DefaultCsrfTokenMixin.class);
		context.setMixInAnnotations(DefaultSavedRequest.class, DefaultSavedRequestMixin.class);
		context.setMixInAnnotations(WebAuthenticationDetails.class, WebAuthenticationDetailsMixin.class);
	}
}
