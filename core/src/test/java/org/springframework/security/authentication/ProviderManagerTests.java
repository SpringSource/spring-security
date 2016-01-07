/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.authentication;

import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;
import org.springframework.context.MessageSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;

/**
 * Tests {@link ProviderManager}.
 *
 * @author Ben Alex
 */
@SuppressWarnings("unchecked")
public class ProviderManagerTests {

	@Test(expected = ProviderNotFoundException.class)
	public void authenticationFailsWithUnsupportedToken() throws Exception {
		Authentication token = new AbstractAuthenticationToken(null) {
			public Object getCredentials() {
				return "";
			}

			public Object getPrincipal() {
				return "";
			}
		};
		ProviderManager mgr = makeProviderManager();
		mgr.setMessageSource(mock(MessageSource.class));
		mgr.authenticate(token);
	}

	@Test
	public void authenticationWithSupportedToken() throws Exception {
		Authentication token = new AbstractAuthenticationToken(null) {
			public Object getCredentials() {
				return "";
			}

			public Object getPrincipal() {
				return "";
			}
		};

		AuthenticationProvider accepts = createProviderWhichReturns(token);

		AuthenticationProvider doesNotSupportClass = mock(AuthenticationProvider.class);
		when(doesNotSupportClass.supports(any(Class.class))).thenReturn(false);
		when(doesNotSupportClass.supports(any(Authentication.class))).thenReturn(false);

		AuthenticationProvider doesNotSupportAuthentication = mock(AuthenticationProvider.class);
		when(doesNotSupportAuthentication.supports(any(Class.class))).thenReturn(true);
		when(doesNotSupportAuthentication.supports(any(Authentication.class))).thenReturn(false);

		ProviderManager mgr = new ProviderManager(Arrays.asList(doesNotSupportClass, doesNotSupportAuthentication, accepts));
		mgr.setMessageSource(mock(MessageSource.class));
		mgr.authenticate(token);

		verify(doesNotSupportClass).supports(token.getClass());
		verify(doesNotSupportClass, never()).supports(token);
		verify(doesNotSupportClass, never()).authenticate(token);

		verify(doesNotSupportAuthentication).supports(token.getClass());
		verify(doesNotSupportAuthentication).supports(token);
		verify(doesNotSupportAuthentication, never()).authenticate(token);

		verify(accepts).supports(token.getClass());
		verify(accepts).supports(token);
		// Authentication is only tried with the supporting provider
		verify(accepts).authenticate(token);
	}

	@Test
	public void credentialsAreClearedByDefault() throws Exception {
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
				"Test", "Password");
		ProviderManager mgr = makeProviderManager();
		Authentication result = mgr.authenticate(token);
		assertNull(result.getCredentials());

		mgr.setEraseCredentialsAfterAuthentication(false);
		token = new UsernamePasswordAuthenticationToken("Test", "Password");
		result = mgr.authenticate(token);
		assertNotNull(result.getCredentials());
	}

	@Test
	public void authenticationSucceedsWithSupportedTokenAndReturnsExpectedObject()
			throws Exception {
		final Authentication a = mock(Authentication.class);
		ProviderManager mgr = new ProviderManager(
				Arrays.asList(createProviderWhichReturns(a)));
		AuthenticationEventPublisher publisher = mock(AuthenticationEventPublisher.class);
		mgr.setAuthenticationEventPublisher(publisher);

		Authentication result = mgr.authenticate(a);
		assertEquals(a, result);
		verify(publisher).publishAuthenticationSuccess(result);
	}

	@Test
	public void authenticationSucceedsWhenFirstProviderReturnsNullButSecondAuthenticates() {
		final Authentication a = mock(Authentication.class);
		ProviderManager mgr = new ProviderManager(Arrays.asList(
				createProviderWhichReturns(null), createProviderWhichReturns(a)));
		AuthenticationEventPublisher publisher = mock(AuthenticationEventPublisher.class);
		mgr.setAuthenticationEventPublisher(publisher);

		Authentication result = mgr.authenticate(a);
		assertSame(a, result);
		verify(publisher).publishAuthenticationSuccess(result);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testStartupFailsIfProvidersNotSet() throws Exception {
		new ProviderManager(null);
	}

	@Test
	public void detailsAreNotSetOnAuthenticationTokenIfAlreadySetByProvider()
			throws Exception {
		Object requestDetails = "(Request Details)";
		final Object resultDetails = "(Result Details)";

		// A provider which sets the details object
		AuthenticationProvider provider = new AuthenticationProvider() {
			public Authentication authenticate(Authentication authentication)
					throws AuthenticationException {
				((TestingAuthenticationToken) authentication).setDetails(resultDetails);
				return authentication;
			}

			public boolean supports(Class<?> authentication) {
				return true;
			}

			public boolean supports(Authentication authentication) {
				return true;
			}
		};

		ProviderManager authMgr = new ProviderManager(Arrays.asList(provider));

		TestingAuthenticationToken request = createAuthenticationToken();
		request.setDetails(requestDetails);

		Authentication result = authMgr.authenticate(request);
		assertEquals(resultDetails, result.getDetails());
	}

	@Test
	public void detailsAreSetOnAuthenticationTokenIfNotAlreadySetByProvider()
			throws Exception {
		Object details = new Object();
		ProviderManager authMgr = makeProviderManager();

		TestingAuthenticationToken request = createAuthenticationToken();
		request.setDetails(details);

		Authentication result = authMgr.authenticate(request);
		assertNotNull(result.getCredentials());
		assertSame(details, result.getDetails());
	}

	@Test
	public void authenticationExceptionIsIgnoredIfLaterProviderAuthenticates()
			throws Exception {
		final Authentication authReq = mock(Authentication.class);
		ProviderManager mgr = new ProviderManager(
				Arrays.asList(createProviderWhichThrows(new BadCredentialsException("",
						new Throwable())), createProviderWhichReturns(authReq)));
		assertSame(authReq, mgr.authenticate(mock(Authentication.class)));
	}

	@Test
	public void authenticationExceptionIsRethrownIfNoLaterProviderAuthenticates()
			throws Exception {

		ProviderManager mgr = new ProviderManager(Arrays.asList(
				createProviderWhichThrows(new BadCredentialsException("")),
				createProviderWhichReturns(null)));
		try {
			mgr.authenticate(mock(Authentication.class));
			fail("Expected BadCredentialsException");
		}
		catch (BadCredentialsException expected) {
		}
	}

	// SEC-546
	@Test
	public void accountStatusExceptionPreventsCallsToSubsequentProviders()
			throws Exception {
		AuthenticationProvider iThrowAccountStatusException = createProviderWhichThrows(new AccountStatusException(
				"") {
		});
		AuthenticationProvider otherProvider = mock(AuthenticationProvider.class);

		ProviderManager authMgr = new ProviderManager(Arrays.asList(
				iThrowAccountStatusException, otherProvider));

		try {
			authMgr.authenticate(mock(Authentication.class));
			fail("Expected AccountStatusException");
		}
		catch (AccountStatusException expected) {
		}
		verifyZeroInteractions(otherProvider);
	}

	@Test
	public void parentAuthenticationIsUsedIfProvidersDontAuthenticate() throws Exception {
		AuthenticationManager parent = mock(AuthenticationManager.class);
		Authentication authReq = mock(Authentication.class);
		when(parent.authenticate(authReq)).thenReturn(authReq);
		ProviderManager mgr = new ProviderManager(
				Arrays.asList(mock(AuthenticationProvider.class)), parent);
		assertSame(authReq, mgr.authenticate(authReq));
	}

	@Test
	public void parentIsNotCalledIfAccountStatusExceptionIsThrown() throws Exception {
		AuthenticationProvider iThrowAccountStatusException = createProviderWhichThrows(new AccountStatusException(
				"", new Throwable()) {
		});
		AuthenticationManager parent = mock(AuthenticationManager.class);
		ProviderManager mgr = new ProviderManager(
				Arrays.asList(iThrowAccountStatusException), parent);
		try {
			mgr.authenticate(mock(Authentication.class));
			fail("Expected exception");
		}
		catch (AccountStatusException expected) {
		}
		verifyZeroInteractions(parent);
	}

	@Test
	public void providerNotFoundFromParentIsIgnored() throws Exception {
		final Authentication authReq = mock(Authentication.class);
		AuthenticationEventPublisher publisher = mock(AuthenticationEventPublisher.class);
		AuthenticationManager parent = mock(AuthenticationManager.class);
		when(parent.authenticate(authReq)).thenThrow(new ProviderNotFoundException(""));

		// Set a provider that throws an exception - this is the exception we expect to be
		// propagated
		ProviderManager mgr = new ProviderManager(
				Arrays.asList(createProviderWhichThrows(new BadCredentialsException(""))),
				parent);
		mgr.setAuthenticationEventPublisher(publisher);

		try {
			mgr.authenticate(authReq);
			fail("Expected exception");
		}
		catch (BadCredentialsException expected) {
			verify(publisher).publishAuthenticationFailure(expected, authReq);
		}
	}

	@Test
	public void authenticationExceptionFromParentOverridesPreviousOnes() throws Exception {
		AuthenticationManager parent = mock(AuthenticationManager.class);
		ProviderManager mgr = new ProviderManager(
				Arrays.asList(createProviderWhichThrows(new BadCredentialsException(""))),
				parent);
		final Authentication authReq = mock(Authentication.class);
		AuthenticationEventPublisher publisher = mock(AuthenticationEventPublisher.class);
		mgr.setAuthenticationEventPublisher(publisher);
		// Set a provider that throws an exception - this is the exception we expect to be
		// propagated
		final BadCredentialsException expected = new BadCredentialsException(
				"I'm the one from the parent");
		when(parent.authenticate(authReq)).thenThrow(expected);
		try {
			mgr.authenticate(authReq);
			fail("Expected exception");
		}
		catch (BadCredentialsException e) {
			assertSame(expected, e);
		}
		verify(publisher).publishAuthenticationFailure(expected, authReq);
	}

	@Test
	@SuppressWarnings("deprecation")
	public void statusExceptionIsPublished() throws Exception {
		AuthenticationManager parent = mock(AuthenticationManager.class);
		final LockedException expected = new LockedException("");
		ProviderManager mgr = new ProviderManager(
				Arrays.asList(createProviderWhichThrows(expected)), parent);
		final Authentication authReq = mock(Authentication.class);
		AuthenticationEventPublisher publisher = mock(AuthenticationEventPublisher.class);
		mgr.setAuthenticationEventPublisher(publisher);
		try {
			mgr.authenticate(authReq);
			fail("Expected exception");
		}
		catch (LockedException e) {
			assertSame(expected, e);
		}
		verify(publisher).publishAuthenticationFailure(expected, authReq);
	}

	// SEC-2367
	@Test
	public void providerThrowsInternalAuthenticationServiceException() {
		InternalAuthenticationServiceException expected = new InternalAuthenticationServiceException(
				"Expected");
		ProviderManager mgr = new ProviderManager(Arrays.asList(
				createProviderWhichThrows(expected),
				createProviderWhichThrows(new BadCredentialsException("Oops"))), null);
		final Authentication authReq = mock(Authentication.class);

		try {
			mgr.authenticate(authReq);
			fail("Expected Exception");
		}
		catch (InternalAuthenticationServiceException success) {
		}
	}

	private AuthenticationProvider createProviderWhichThrows(
			final AuthenticationException e) {
		AuthenticationProvider provider = mock(AuthenticationProvider.class);
		when(provider.supports(any(Class.class))).thenReturn(true);
		when(provider.supports(any(Authentication.class))).thenReturn(true);
		when(provider.authenticate(any(Authentication.class))).thenThrow(e);

		return provider;
	}

	private AuthenticationProvider createProviderWhichReturns(final Authentication a) {
		AuthenticationProvider provider = mock(AuthenticationProvider.class);
		when(provider.supports(any(Class.class))).thenReturn(true);
		when(provider.supports(any(Authentication.class))).thenReturn(true);
		when(provider.authenticate(any(Authentication.class))).thenReturn(a);

		return provider;
	}

	private TestingAuthenticationToken createAuthenticationToken() {
		return new TestingAuthenticationToken("name", "password",
				new ArrayList<GrantedAuthority>(0));
	}

	private ProviderManager makeProviderManager() throws Exception {
		MockProvider provider1 = new MockProvider();
		List<AuthenticationProvider> providers = new ArrayList<AuthenticationProvider>();
		providers.add(provider1);

		return new ProviderManager(providers);
	}

	// ~ Inner Classes
	// ==================================================================================================

	private class MockProvider implements AuthenticationProvider {
		public Authentication authenticate(Authentication authentication)
				throws AuthenticationException {
			if (supports(authentication.getClass())) {
				return authentication;
			}
			else {
				throw new AuthenticationServiceException("Don't support this class");
			}
		}

		public boolean supports(Class<?> authentication) {
			return TestingAuthenticationToken.class.isAssignableFrom(authentication)
					|| UsernamePasswordAuthenticationToken.class
							.isAssignableFrom(authentication);
		}

		public boolean supports(Authentication authentication) {
			return true;
		}
	}
}
