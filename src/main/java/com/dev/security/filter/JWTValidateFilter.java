package com.dev.security.filter;

import com.dev.security.model.JWTValidationToken;
import com.dev.security.util.JWTUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JWTValidateFilter extends OncePerRequestFilter {

    JWTUtil jwtUtil;
    AuthenticationManager authenticationManager;

    public JWTValidateFilter( AuthenticationManager authenticationManager,JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        //fetch the token.
        String jwtToken = jwtUtil.extractJwtTokenFromRequest(request);

        if (jwtToken == null)
        {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid Credentials");
        }

        try
        {
            //Create the Authentication Object and validate the Authentication object by delegating to Authentication Provider
            JWTValidationToken jwtAuthObj = new JWTValidationToken(jwtToken);
            Authentication authObj = authenticationManager.authenticate(jwtAuthObj);

            //Create the SecurityContext with Authenticated Object.
            SecurityContextHolder.getContext().setAuthentication(authObj);
            filterChain.doFilter(request, response);
        }
        catch (Exception ex)
        {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid Credentials");
        }
    }
}
