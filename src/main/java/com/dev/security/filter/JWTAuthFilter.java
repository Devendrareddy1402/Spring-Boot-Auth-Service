package com.dev.security.filter;

import com.dev.security.dao.LoginRequest;
import com.dev.security.util.JWTUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.filter.OncePerRequestFilter;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;

/**
 *  For handles the user login design
 *  /auth/generateToken end point
 */
public class JWTAuthFilter extends OncePerRequestFilter {

     private final AuthenticationManager authenticationManager;
     private final JWTUtil jwtUtil;

     public JWTAuthFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil)
     {
         this.authenticationManager = authenticationManager;
         this.jwtUtil = jwtUtil;
     }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain
    ) throws ServletException, IOException {

         if(!request.getServletPath().equals("/auth/generateToken"))
         {
             filterChain.doFilter(request, response);
             return;
         }

        // parse the request and fetch userName and password;
        ObjectMapper objectMapper = new ObjectMapper();
        LoginRequest loginRequest = objectMapper.readValue(request.getInputStream(), LoginRequest.class);

        try
        {
            // Create Authentication Object
            UsernamePasswordAuthenticationToken authObj = new UsernamePasswordAuthenticationToken(loginRequest.getEmail(),
                    loginRequest.getPassword());

            // validate Authentication object by delegating authObj to Authentication Manager
            Authentication authResult = authenticationManager.authenticate(authObj);

            if(authResult.isAuthenticated())
            {
                // generate jwt token
                String jwtToken = jwtUtil.generateToken(authResult.getName());
                response.setHeader("Authorization", "Bearer " + jwtToken);
                response.setStatus(HttpServletResponse.SC_OK);
            }

        }
        catch (Exception e)
        {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid Credentials");
        }
    }
}
