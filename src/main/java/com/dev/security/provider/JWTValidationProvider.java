package com.dev.security.provider;

import com.dev.security.model.JWTValidationToken;
import com.dev.security.service.JWTService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SecurityException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;


public class JWTValidationProvider implements AuthenticationProvider {

    private final JWTService jwtService;
    private final UserDetailsService userDetailsService;

    public JWTValidationProvider(JWTService jwtService, UserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        JWTValidationToken authObj = (JWTValidationToken) authentication;
        String jwtToken = authObj.getToken();

        try
        {
            String email = jwtService.extractEmail(jwtToken);
            UserDetails userDetails = userDetailsService.loadUserByUsername(email);

            if (!email.equals(userDetails.getUsername()))
            {
                throw new BadCredentialsException("Invalid token");
            }

            return new JWTValidationToken(userDetails, userDetails.getAuthorities());
        }
        catch(ExpiredJwtException ex)
        {
            throw new CredentialsExpiredException("Token has expired");
        }
        catch(MalformedJwtException | SecurityException ex)
        {
            throw new BadCredentialsException("Invalid token");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JWTValidationToken.class.isAssignableFrom(authentication);
    }
}
