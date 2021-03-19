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

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

import javax.servlet.http.HttpServletRequest;

import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnRequestMarshaller;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDBuilder;
import org.w3c.dom.Element;

import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2PostAuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * A strategy for resolving a SAML 2.0 Authentication Request from the
 * {@link HttpServletRequest} using OpenSAML.
 *
 * @author Josh Cummings
 * @since 5.5
 */
public class OpenSamlAuthenticationRequestResolver implements Saml2AuthenticationRequestResolver {

	private final RelyingPartyRegistrationResolver relyingPartyRegistrationResolver;

	private RequestMatcher requestMatcher = new AntPathRequestMatcher("/saml2/authenticate/{registrationId}");

	/**
	 * Construct a {@link OpenSamlAuthenticationRequestResolver} using the provided
	 * parameters
	 * @param relyingPartyRegistrationResolver a strategy for resolving the
	 * {@link RelyingPartyRegistration} from the {@link HttpServletRequest}
	 */
	public OpenSamlAuthenticationRequestResolver(RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
		Assert.notNull(relyingPartyRegistrationResolver, "relyingPartyRegistrationResolver cannot be null");
		this.relyingPartyRegistrationResolver = relyingPartyRegistrationResolver;
	}

	public void setRequestMatcher(RequestMatcher requestMatcher) {
		Assert.notNull(requestMatcher, "requestMatcher cannot be null");
		this.requestMatcher = requestMatcher;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public OpenSamlAuthenticationRequestPartial resolveAuthenticationRequest(HttpServletRequest request) {
		RequestMatcher.MatchResult result = this.requestMatcher.matcher(request);
		if (!result.isMatch()) {
			return null;
		}
		String registrationId = this.requestMatcher.matcher(request).getVariables().get("registrationId");
		RelyingPartyRegistration registration = this.relyingPartyRegistrationResolver.resolve(request, registrationId);
		if (registration == null) {
			return null;
		}
		return new OpenSamlAuthenticationRequestPartial(registration);
	}

	public static final class OpenSamlAuthenticationRequestPartial
			implements Saml2AuthenticationRequestPartial<OpenSamlAuthenticationRequestPartial> {

		static {
			OpenSamlInitializationService.initialize();
		}

		private final AuthnRequestMarshaller marshaller;

		private final IssuerBuilder issuerBuilder;

		private final NameIDBuilder nameIdBuilder;

		private final RelyingPartyRegistration registration;

		private final AuthnRequest authnRequest;

		private String relayState;

		public OpenSamlAuthenticationRequestPartial(RelyingPartyRegistration registration) {
			this.registration = registration;
			XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
			this.marshaller = (AuthnRequestMarshaller) registry.getMarshallerFactory()
					.getMarshaller(AuthnRequest.DEFAULT_ELEMENT_NAME);
			Assert.notNull(this.marshaller, "logoutRequestMarshaller must be configured in OpenSAML");
			AuthnRequestBuilder authnRequestBuilder = (AuthnRequestBuilder) XMLObjectProviderRegistrySupport
					.getBuilderFactory().getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
			Assert.notNull(authnRequestBuilder, "authnRequestBuilder must be configured in OpenSAML");
			this.issuerBuilder = (IssuerBuilder) registry.getBuilderFactory().getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
			Assert.notNull(this.issuerBuilder, "issuerBuilder must be configured in OpenSAML");
			this.nameIdBuilder = (NameIDBuilder) registry.getBuilderFactory().getBuilder(NameID.DEFAULT_ELEMENT_NAME);
			Assert.notNull(this.nameIdBuilder, "nameIdBuilder must be configured in OpenSAML");
			AuthnRequest authnRequest = authnRequestBuilder.buildObject();
			authnRequest.setForceAuthn(Boolean.FALSE);
			authnRequest.setIsPassive(Boolean.FALSE);
			authnRequest.setProtocolBinding(registration.getAssertionConsumerServiceBinding().getUrn());
			Issuer iss = this.issuerBuilder.buildObject();
			iss.setValue(registration.getEntityId());
			authnRequest.setIssuer(iss);
			authnRequest.setDestination(registration.getAssertingPartyDetails().getSingleSignOnServiceLocation());
			authnRequest.setAssertionConsumerServiceURL(registration.getAssertionConsumerServiceLocation());
			this.authnRequest = authnRequest;
		}

		@Override
		public OpenSamlAuthenticationRequestPartial relayState(String relayState) {
			this.relayState = relayState;
			return this;
		}

		public OpenSamlAuthenticationRequestPartial authnRequest(Consumer<AuthnRequest> authnRequestConsumer) {
			authnRequestConsumer.accept(this.authnRequest);
			return this;
		}

		@Override
		public AbstractSaml2AuthenticationRequest request() {
			if (this.authnRequest.getID() == null) {
				this.authnRequest.setID("ARQ" + UUID.randomUUID().toString().substring(1));
			}
			if (this.relayState == null) {
				this.relayState = UUID.randomUUID().toString();
			}
			Saml2MessageBinding binding = this.registration.getAssertingPartyDetails().getSingleSignOnServiceBinding();
			if (binding == Saml2MessageBinding.POST) {
				if (this.registration.getAssertingPartyDetails().getWantAuthnRequestsSigned()) {
					OpenSamlSigningUtils.sign(this.authnRequest, this.registration);
				}
				String xml = serialize(this.authnRequest);
				String encoded = Saml2Utils.samlEncode(xml.getBytes(StandardCharsets.UTF_8));
				return Saml2PostAuthenticationRequest.withRelyingPartyRegistration(this.registration)
						.samlRequest(encoded).relayState(this.relayState).build();
			}
			else {
				String xml = serialize(this.authnRequest);
				String deflatedAndEncoded = Saml2Utils.samlEncode(Saml2Utils.samlDeflate(xml));
				Saml2RedirectAuthenticationRequest.Builder builder = Saml2RedirectAuthenticationRequest
						.withRelyingPartyRegistration(this.registration).samlRequest(deflatedAndEncoded)
						.relayState(this.relayState);
				if (this.registration.getAssertingPartyDetails().getWantAuthnRequestsSigned()) {
					Map<String, String> parameters = OpenSamlSigningUtils.sign(this.registration)
							.param("SAMLRequest", deflatedAndEncoded).param("RelayState", this.relayState).parameters();
					builder.sigAlg(parameters.get("SigAlg")).signature(parameters.get("Signature"));
				}
				return builder.build();
			}
		}

		private String serialize(AuthnRequest authnRequest) {
			try {
				Element element = this.marshaller.marshall(authnRequest);
				return SerializeSupport.nodeToString(element);
			}
			catch (MarshallingException ex) {
				throw new Saml2Exception(ex);
			}
		}

	}

}
