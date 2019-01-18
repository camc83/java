package com.umantis.seniordev.security.jwt;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URLEncoder;
import java.text.ParseException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.util.ReflectionTestUtils;

import com.umantis.seniordev.security.jwt.JWTAuthenticationService;
import com.umantis.seniordev.security.jwt.JWTTokenHandler;
import com.umantis.seniordev.security.jwt.JWTTokenHandlerFactory;
import com.umantis.seniordev.security.jwt.JWTUserInfo;
import com.umantis.seniordev.security.jwt.UserAuthentication;

@RunWith(MockitoJUnitRunner.class)
public class JWTAuthenticationServiceTest {

    static final String TEST_KEY = "9SyECk96oDsTmXfogIieDI0cD/8FpnojlYSUJT5U9I/FGVmBz5oskmjOR8cbXTvoPjX+Pq/T/b1PqpHX0lYm0oCBjXWICA==";

    @Mock
    private HttpServletRequest req;
    @Mock
    private HttpServletResponse resp;
    private final JWTUserInfo jwtUserInfo = new JWTUserInfo();

    private UserAuthentication authentication;
    private JWTAuthenticationService service;
    private JWTTokenHandler jwtTokenHandler;
    private JWTUserInfo userInfo;
    private String token;

    // given
    // when
    // then

    @Before
    public void setUp() {
        this.jwtUserInfo.setUserId("1000");
        this.jwtUserInfo.setUserName("someone");
        this.authentication = new UserAuthentication(this.jwtUserInfo);
        this.service = new JWTAuthenticationService();
        JWTTokenHandlerFactory factory = new JWTTokenHandlerFactory(TEST_KEY);
        this.jwtTokenHandler = factory.createForAlgorithm(JWTTokenHandlerFactory.KnownAlgorithms.HS256);
        ReflectionTestUtils.setField(this.service, "tokenHandlerFactory", factory);
        this.userInfo = new JWTUserInfo();
        this.userInfo.setUserId("1000");
        this.userInfo.setUserName("UserNumber1000");
        Set<String> roles = new HashSet<String>();
        roles.add("ROLE_TEST1");
        roles.add("ROLE_TEST2");
        this.userInfo.setRoles(roles);
        this.token = this.jwtTokenHandler.createAuthToken(this.userInfo);
    }

    @Test
    public void testAddAuthentication1() {
        // given
        // when
        this.service.addAuthentication(this.req, this.resp, null);
        // then
        verify(this.resp, times(1)).addHeader(anyString(), anyString());
    }

    @Test
    public void testAddAuthentication2() {
        // given
        long expires1 = this.jwtUserInfo.getExpires();
        // when
        this.service.addAuthentication(this.req, this.resp, this.authentication);
        // then
        verify(this.resp).addHeader(eq("X-AUTH-TOKEN"), anyString());
        long expires2 = this.jwtUserInfo.getExpires();
        assertEquals(expires1, expires2);
    }

    @Test
    public void testGetAuthenticationTokenValidation1() {
        // given
        when(this.req.getHeader(JWTAuthenticationService.JWT_HEADER_NAME)).thenReturn(null);
        // when
        Authentication auth = this.service.getAuthentication(this.req);
        // then
        assertNull(auth);
    }

    @Test
    public void testGetAuthenticationTokenValidation2() {
        // given
        when(this.req.getHeader(JWTAuthenticationService.JWT_HEADER_NAME)).thenReturn(null);
        when(this.req.getCookies()).thenReturn(new Cookie[] {});
        // when
        Authentication auth = this.service.getAuthentication(this.req);
        // then
        assertNull(auth);
    }


    @Test
    public void testAdditionalChecks2() {
        // given
        this.userInfo.setUserId("0");
        this.token = this.jwtTokenHandler.createAuthToken(this.userInfo);
        when(this.req.getHeader(JWTAuthenticationService.JWT_HEADER_NAME)).thenReturn(this.token);
        // when
        Authentication auth = this.service.getAuthentication(this.req);
        // then
        assertNull(auth);
    }

    @Test
    public void testGetAuthorities1() throws NoSuchMethodException, SecurityException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        // given
        Method getAuthoritiesMethod = this.service.getClass().getDeclaredMethod("getAuthorities", Set.class);
        getAuthoritiesMethod.setAccessible(true);
        // when
        Object o = getAuthoritiesMethod.invoke(this.service, this.userInfo.getRoles());
        // then
        @SuppressWarnings("unchecked")
        Collection<SimpleGrantedAuthority> authrorities = (Collection<SimpleGrantedAuthority>) o;
        assertEquals(2, authrorities.size());
        authrorities.contains("ROLE_TEST1_Mapped");
        authrorities.contains("ROLE_TEST2_Mapped");
    }

    @Test
    public void testGetAuthorities2() throws NoSuchMethodException, SecurityException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        // given
        Method getAuthoritiesMethod = this.service.getClass().getDeclaredMethod("getAuthorities", Set.class);
        getAuthoritiesMethod.setAccessible(true);
        this.userInfo.getRoles().add("Restricted");
        // when
        Object o = getAuthoritiesMethod.invoke(this.service, this.userInfo.getRoles());
        // then
        @SuppressWarnings("unchecked")
        Collection<SimpleGrantedAuthority> authorities = (Collection<SimpleGrantedAuthority>) o;
        assertEquals(2, authorities.size());
        authorities.contains("ROLE_TEST1Restricted_Mapped");
        authorities.contains("ROLE_TEST2Restricted_Mapped");
    }

    @Test
    public void testGetAuthentication() {
        // given
        when(this.req.getHeader(JWTAuthenticationService.JWT_HEADER_NAME)).thenReturn(this.token);
        // when
        Authentication a = this.service.getAuthentication(this.req);
        // then
        UserAuthentication ua = (UserAuthentication) a;
        assertEquals(this.userInfo.getUsername(), ua.getName());
        Collection<? extends GrantedAuthority> authorities = ua.getAuthorities();
        assertEquals(2, authorities.size());
        authorities.contains("ROLE_TEST1Restricted_Mapped");
        authorities.contains("ROLE_TEST2Restricted_Mapped");
        assertEquals(this.userInfo.getUserId(), ua.getPrincipal());
        assertTrue(ua.isAuthenticated());
    }

}
