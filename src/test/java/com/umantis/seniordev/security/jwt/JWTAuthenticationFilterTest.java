package com.umantis.seniordev.security.jwt;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.util.ReflectionTestUtils;

import com.umantis.seniordev.security.jwt.JWTAuthenticationFilter;
import com.umantis.seniordev.security.jwt.JWTAuthenticationService;
import com.umantis.seniordev.security.jwt.JWTTokenHandler;
import com.umantis.seniordev.security.jwt.JWTTokenHandlerFactory;
import com.umantis.seniordev.security.jwt.JWTUserInfo;
import com.umantis.seniordev.security.jwt.UserAuthentication;

@RunWith(MockitoJUnitRunner.class)
public class JWTAuthenticationFilterTest {

    static final String TEST_KEY = "9SyECk96oDsTmXfogIieDI0cD/8FpnojlYSUJT5U9I/FGVmBz5oskmjOR8cbXTvoPjX+Pq/T/b1PqpHX0lYm0oCBjXWICA==";
    private JWTAuthenticationService authService;
    @Mock
    private HttpServletRequest req;
    @Mock
    private HttpServletResponse resp;
    @Mock
    private FilterChain chain;

    private JWTAuthenticationFilter filter;
    private UserAuthentication authentication;
    private JWTTokenHandler jwtTokenHandler;
    private JWTUserInfo userInfo;
    private String token;

    @Before
    public void setUp() {
        JWTTokenHandlerFactory factory = new JWTTokenHandlerFactory(TEST_KEY);
        this.jwtTokenHandler = factory.createForAlgorithm(JWTTokenHandlerFactory.KnownAlgorithms.HS256);
        this.authService = new JWTAuthenticationService();
        ReflectionTestUtils.setField(this.authService, "tokenHandlerFactory", factory);
        this.filter = new JWTAuthenticationFilter(this.authService);
        this.userInfo = new JWTUserInfo();
        this.userInfo.setUserId("1000");
        this.userInfo.setUserName("UserNumber1000");
        Set<String> roles = new HashSet<String>();
        roles.add("ROLE_TEST1");
        roles.add("ROLE_TEST2");
        this.userInfo.setRoles(roles);
        long now = System.currentTimeMillis();
        this.userInfo.setCreated(now);
        this.userInfo.setExpires(now + 1000000L);
        this.token = this.jwtTokenHandler.createAuthToken(this.userInfo);
    }

    @Test
    public void testDoFilter1() throws IOException, ServletException {
        when(this.authService.getAuthentication(this.req)).thenReturn(this.authentication);
        this.filter.doFilter(this.req, this.resp, this.chain);
        verify(this.chain).doFilter(this.req, this.resp);
        assertEquals(SecurityContextHolder.getContext().getAuthentication(), this.authentication);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testDoFilter2() throws IOException, ServletException {
        when(this.authService.getAuthentication(this.req)).thenThrow(AuthenticationCredentialsNotFoundException.class);
        this.filter.doFilter(this.req, this.resp, this.chain);
        verify(this.chain, times(0)).doFilter(this.req, this.resp);
        verify(this.resp).sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
    }

    @Test
    public void testCompareTokenBeforeAndAfter() throws IOException, ServletException {
        // given
        when(this.req.getHeader(JWTAuthenticationService.JWT_HEADER_NAME)).thenReturn(this.token);
        MockHttpServletResponse response = new MockHttpServletResponse();
        // when
        this.filter.doFilter(this.req, response, this.chain);
        // then
        String newToken = response.getHeader(JWTAuthenticationService.JWT_HEADER_NAME);
        JWTUserInfo userInfo2 = this.jwtTokenHandler.parseAuthToken(newToken);
        assertEquals(userInfo2.getRoles(), this.userInfo.getRoles());
        assertEquals(userInfo2.getUserId(), this.userInfo.getUserId());
        assertEquals(userInfo2.getUserName(), this.userInfo.getUserName());
        assertEquals(userInfo2.getExpires(), this.userInfo.getExpires());
    }

}
