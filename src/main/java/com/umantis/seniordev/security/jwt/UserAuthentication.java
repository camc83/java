package com.umantis.seniordev.security.jwt;

import java.util.Collection;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

/**
 * 
 * @author mac
 *
 */
public class UserAuthentication implements Authentication {

    private static final long serialVersionUID = 1L;
    private final JWTUserInfo user;

    public UserAuthentication(final JWTUserInfo user) {
        this.user = user;
    }

    @Override
    public String getName() {
        return this.user.getUserName();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.user.getAuthorities();
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public JWTUserInfo getDetails() {
        return this.user;
    }

    @Override
    public Object getPrincipal() {
        return this.user.getUserId();
    }

    @Override
    public boolean isAuthenticated() {
        return this.user.getUserId() != null;
    }

    @Override
    public void setAuthenticated(final boolean authenticated) {
    }
}
