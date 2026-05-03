package com.dev.security.service;

import com.dev.security.dto.LoginRequest;
import com.dev.security.dto.LoginResponse;
import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class UserService {

    @Autowired
    private JWTService jwtService;
    @Autowired
    private AuthenticationManager authenticationManager;

    public LoginResponse handleLogin(LoginRequest loginRequest)
    {

        try {
            UsernamePasswordAuthenticationToken authObj = new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword());
            Authentication authRes = authenticationManager.authenticate(authObj);

            String jwtToken = jwtService.generateToken(authRes.getName());
            Date expireTime = jwtService.extractExpirationTime(jwtToken);

            return new LoginResponse(jwtToken, expireTime);
        }
        catch (Exception e)
        {
            throw new BadCredentialsException("Invalid credentials");
        }
    }
}
