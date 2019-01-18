package com.umantis.seniordev.security.jwt;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

/**
 *
 * @author mac
 *
 */
public class JWTAuthenticationFilter extends GenericFilterBean {

    private final JWTAuthenticationService authService;

    public JWTAuthenticationFilter(final JWTAuthenticationService authService) {
        this.authService = authService;
    }

    @Override
    public void doFilter(final ServletRequest req, final ServletResponse res, final FilterChain chain) throws IOException, ServletException {
        try {
            Authentication auth = this.authService.getAuthentication((HttpServletRequest) req);
            this.authService.addAuthentication((HttpServletRequest) req, (HttpServletResponse) res, auth);
            SecurityContextHolder.getContext().setAuthentication(auth);
            chain.doFilter(req, res); // always continue
        } catch (AuthenticationCredentialsNotFoundException e) {
            ((HttpServletResponse) res).sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
        }
    }
}
