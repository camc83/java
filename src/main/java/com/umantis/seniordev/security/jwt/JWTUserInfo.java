package com.umantis.seniordev.security.jwt;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 *
 * @author Gergely.Szakacs
 *
 */
public class JWTUserInfo implements UTMUserInfo {

    /**
     * Class for JWT claim names.
     *
     * @author Gergely.Szakacs
     *
     */
    public class JwtClaims {

        public static final String USER_NAME = "uname";
        public static final String USER_ID = "uid";
        public static final String ROLES = "roles";
        public static final String CREATED = "created";
        public static final String EXPIRES = "expires";
    }

    private static final long serialVersionUID = 1L;
    @JsonProperty(JwtClaims.USER_NAME)
    private String userName;
    @JsonProperty(JwtClaims.USER_ID)
    private String userId;
    @JsonProperty(JwtClaims.ROLES)
    private Set<String> roles = new HashSet<>();
    @JsonProperty(JwtClaims.CREATED)
    private long created;
    @JsonProperty(JwtClaims.EXPIRES)
    private long expires;

    private Collection<? extends GrantedAuthority> authorities;

    @Override
    public String getUserName() {
        return this.userName;
    }

    public void setUserName(final String userName) {
        this.userName = userName;
    }

    @Override
    public String getUserId() {
        return this.userId;
    }

    public void setUserId(final String userId) {
        this.userId = userId;
    }

    @Override
    public Set<String> getRoles() {
        return this.roles;
    }

    public void setRoles(final Set<String> roles) {
        this.roles = roles;
    }

    public void setAuthorities(final Collection<? extends GrantedAuthority> authorities) {
        this.authorities = authorities;
    }

    @JsonIgnore
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @JsonIgnore
    @Override
    public String getPassword() {
        return "";
    }

    @JsonIgnore
    @Override
    public String getUsername() {
        return this.userName;
    }

    @JsonIgnore
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @JsonIgnore
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @JsonIgnore
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @JsonIgnore
    @Override
    public boolean isEnabled() {
        return true;
    }

    @JsonIgnore
    @Override
	public long getCreated() {
		return created;
	}

	public void setCreated(long created) {
		this.created = created;
	}

    @JsonIgnore
    @Override
	public long getExpires() {
		return expires;
	}

	public void setExpires(long expires) {
		this.expires = expires;
	}

}