package com.umantis.seniordev.security.jwt;

import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.StringUtils;
import com.google.common.util.concurrent.UncheckedExecutionException;

/**
 *
 * @author Gergely.Szakacs
 *
 */
public class JWTAuthenticationService {

    public static final String JWT_HEADER_NAME = "X-AUTH-TOKEN";
    private static final Logger AUDIT = LoggerFactory.getLogger("audit");
    private static final Logger LOG = LoggerFactory.getLogger(JWTAuthenticationService.class);

    @Autowired
    private JWTTokenHandlerFactory tokenHandlerFactory;
    private JWTTokenHandler tokenHandler;

    public JWTAuthenticationService() {
    }

    public JWTAuthenticationService(final boolean apiDebugMode) {
    }

    /**
     * Adds the same JWT token to the response headers.
     *
     * @param request
     *            the servlet request
     * @param response
     *            the servlet response
     * @param authentication
     *            the authenticated user
     */
    public void addAuthentication(final HttpServletRequest request, final HttpServletResponse response, final Authentication authentication) {
        response.addHeader(JWT_HEADER_NAME, request.getHeader(JWT_HEADER_NAME));
    }

    /**
     * Extracts a user from the JWT token if the token is valid.
     *
     * @param request
     *            the current servlet request
     * @return authenticated user
     */
    public Authentication getAuthentication(final HttpServletRequest request) {
        String token = request.getHeader(JWT_HEADER_NAME);
        if (token != null) {
            JWTUserInfo user = getTokenHandler(token).parseAuthToken(token);
            if (user != null) {
                if (performAdditionalChecks(user)) {
                    return createUserAuthentication(user);
                }
            }
        }
        return null;
    }

    private boolean performAdditionalChecks(final JWTUserInfo user) {
        if ((user.getUserId() == null) || (Integer.valueOf(user.getUserId()) == 0) || StringUtils.isEmpty(user.getUserName())) {
            AUDIT.warn("Login attempt failed: missing userId or userName");
        } else if ((new Date().getTime() / 1000L) >= user.getExpires()) {
            AUDIT.info("Login failed for {}-{}[{}] failed: token timeout", user.getUsername(), user.getUserId());
        } else {
            return true;
        }
        return false;
    }

    private JWTTokenHandler getTokenHandler(final String token) {
        if (this.tokenHandler == null) {
            this.tokenHandler = this.tokenHandlerFactory.createForToken(token);
        }
        return this.tokenHandler;
    }

    private Authentication createUserAuthentication(final JWTUserInfo user) {
        try {
            user.setAuthorities(getAuthorities(user.getRoles()));
        } catch (UncheckedExecutionException e) {
            LOG.error("Service unavailable", e);
            AUDIT.info("Service unavailable");
            throw new AuthenticationCredentialsNotFoundException("Service unavailable", e);
        }
        LOG.debug("Successful login for {}-{}[{}]", user.getUsername(), user.getUserId());
        return new UserAuthentication(user);
    }

    /**
     * Transform and create list of authorities.
     *
     * @param roles
     *            Retrieved rolse
     * @return
     *         Mapped roles.
     */
    public Collection<SimpleGrantedAuthority> getAuthorities(final Set<String> roles) {
        final Collection<SimpleGrantedAuthority> authorities = new HashSet<SimpleGrantedAuthority>();
        final boolean isRestricted = roles.contains("Restricted");
        for (final String role : roles) {
            if (!"Restricted".equals(role)) {
                final String actualRole = isRestricted ? (role + "Restricted") : role;
                authorities.add(new SimpleGrantedAuthority(actualRole));
            }
        }
        return authorities;
    }

}
