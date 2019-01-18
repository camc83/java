package com.umantis.seniordev.authentication;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.text.ParseException;
import java.util.List;
import org.fest.assertions.Assertions;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.StringUtils;
import org.springframework.web.context.WebApplicationContext;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.umantis.seniordev.WebAppContext;
import com.umantis.seniordev.security.jwt.JWTUserInfo.JwtClaims;
import com.umantis.seniordev.util.TestConstants;
import com.umantis.seniordev.util.TestContext;
import com.umantis.seniordev.util.TestUtils;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = { TestContext.class, WebAppContext.class })
@WebAppConfiguration
public class AuthenticationControllerTest {

	private MockMvc mockMvc;

	@Autowired
	private WebApplicationContext webApplicationContext;
	
	@Before
	public void setUp() {
		// you can modify the mockMvc creation if needed
        this.mockMvc = MockMvcBuilders.webAppContextSetup(this.webApplicationContext).build();
    }

	@Test
	public void testCersei() throws Exception {
		// given
		// when
        MockHttpServletResponse response = this.mockMvc
                .perform(TestUtils.createAuthGet(TestConstants.USERNAME_CERSEI, TestConstants.PASS_CERSEI))
                .andExpect(status().isOk()).andExpect(content().contentType(TestConstants.APPLICATION_JSON_UTF8))
                .andReturn().getResponse();
        // then
		String authToken = TestUtils.getAuthToken(response);
		JWTClaimsSet claimsSet = parseAndVerify(authToken);

        assertTokenCreationAndExpiration(claimsSet);

        String userName = claimsSet.getStringClaim(JwtClaims.USER_NAME);
        assertEquals(userName, TestConstants.USERNAME_CERSEI);

        @SuppressWarnings("unchecked")
        List<String> roles = (List<String>) claimsSet.getClaim(JwtClaims.ROLES);
        Assertions.assertThat(roles).containsOnly("Queen Regent", "Queen Dowager", "Protector of the Realm", "Lady of Casterly Rock");

        String userId = claimsSet.getStringClaim(JwtClaims.USER_ID);
        assertTrue(Long.parseLong(userId) > 1000L);
    }

    public void assertTokenCreationAndExpiration(final JWTClaimsSet claimsSet) throws ParseException {
        Long created = claimsSet.getLongClaim(JwtClaims.CREATED);
        assertTrue(created + 1_000 > System.currentTimeMillis());

        Long expires = claimsSet.getLongClaim(JwtClaims.EXPIRES);
        assertTrue(expires + 1_001_000 > System.currentTimeMillis());
    }

    @Test
    public void testSansa() throws Exception {
        // given
		// when
        MockHttpServletResponse response = this.mockMvc
                .perform(TestUtils.createAuthGet(TestConstants.USERNAME_SANSA, TestConstants.PASS_SANSA))
                .andExpect(status().isOk()).andExpect(content().contentType(TestConstants.APPLICATION_JSON_UTF8))
                .andReturn().getResponse();

		// then
		String authToken = TestUtils.getAuthToken(response);
		JWTClaimsSet claimsSet = parseAndVerify(authToken);

        assertTokenCreationAndExpiration(claimsSet);

        assertEquals(claimsSet.getStringClaim(JwtClaims.USER_NAME), TestConstants.USERNAME_SANSA);

        @SuppressWarnings("unchecked")
        List<String> roles = (List<String>) claimsSet.getClaim(JwtClaims.ROLES);
        Assertions.assertThat(roles).containsOnly("Lady of Winterfell");

        String userId = claimsSet.getStringClaim(JwtClaims.USER_ID);
        assertTrue(Long.parseLong(userId) > 1_000L);
    }

	@Test
	public void testWalda() throws Exception {
		// given
		// when
        MockHttpServletResponse response = this.mockMvc
                .perform(TestUtils.createAuthGet(TestConstants.USERNAME_WALDA, TestConstants.PASS_WALDA))
                .andExpect(status().isOk()).andExpect(content().contentType(TestConstants.APPLICATION_JSON_UTF8))
                .andReturn().getResponse();

		// then
		String authToken = TestUtils.getAuthToken(response);
		JWTClaimsSet claimsSet = parseAndVerify(authToken);

        assertTokenCreationAndExpiration(claimsSet);

        assertEquals(claimsSet.getStringClaim(JwtClaims.USER_NAME), TestConstants.USERNAME_WALDA);

        @SuppressWarnings("unchecked")
        List<String> roles = (List<String>) claimsSet.getClaim(JwtClaims.ROLES);
        Assertions.assertThat(roles).isEmpty();

        String userId = claimsSet.getStringClaim(JwtClaims.USER_ID);
        assertTrue(Long.parseLong(userId) > 1_000L);
    }

	private JWTClaimsSet parseAndVerify(String authToken) throws ParseException, JOSEException {
		SignedJWT decodedSignedJWT = SignedJWT.parse(authToken);
        JWSVerifier verifier = new MACVerifier(new Base64(TestConstants.HS256_SECRET).decode());
        assertTrue(decodedSignedJWT.verify(verifier));
        return decodedSignedJWT.getJWTClaimsSet();
    }

	@Test
	public void testYgritte() throws Exception {
		// given
		// when
        String content = this.mockMvc.perform(TestUtils.createAuthGet(TestConstants.USERNAME_YGRITTE, TestConstants.WRONG_PASS_YGRITTE))
                .andExpect(status().isUnauthorized()).andExpect(content().contentType(TestConstants.APPLICATION_JSON_UTF8))
                .andReturn().getResponse().getContentAsString();
        // then
		assertTrue(StringUtils.isEmpty(content));
	}

}
