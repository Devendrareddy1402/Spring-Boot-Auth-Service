package com.dev.security.model;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import javax.security.auth.Subject;
import java.util.Collection;

public class JWTValidationToken extends AbstractAuthenticationToken {

    private String token;
    private Object principal;

    public JWTValidationToken(String token) {
        super(null);
        this.token = token;
        setAuthenticated(false);
    }

    public JWTValidationToken(Object principal, Collection<? extends GrantedAuthority> authorities)
    {
        super(authorities);
        this.principal = principal;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return token;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    @Override
    public boolean implies(Subject subject) {
        return super.implies(subject);
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
}
