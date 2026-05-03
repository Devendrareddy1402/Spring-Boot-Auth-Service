package com.dev.security.filter;

import com.dev.security.model.JWTValidationToken;
import com.dev.security.service.JWTService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JWTValidateFilter extends OncePerRequestFilter {

    JWTService jwtService;
    AuthenticationManager authenticationManager;

    public JWTValidateFilter(AuthenticationManager authenticationManager, JWTService jwtService) {
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        //fetch the token.
        String jwtToken = jwtService.extractJwtTokenFromRequest(request);

        if (jwtToken == null) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            //Create the Authentication Object and validate the Authentication object by delegating to Authentication Provider
            JWTValidationToken jwtAuthObj = new JWTValidationToken(jwtToken);
            Authentication authObj = authenticationManager.authenticate(jwtAuthObj);

            //Create the SecurityContext with Authenticated Object.
            SecurityContextHolder.getContext().setAuthentication(authObj);
            filterChain.doFilter(request, response);
        } catch (CredentialsExpiredException | BadCredentialsException | UsernameNotFoundException ex) {
            request.setAttribute("exception", ex);
            throw ex;
        }
    }
}
