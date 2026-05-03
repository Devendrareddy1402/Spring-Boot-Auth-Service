package com.dev.security.service;

import com.dev.security.dto.LoginRequest;
import com.dev.security.dto.LoginResponse;
import com.dev.security.model.RefreshToken;
import com.dev.security.model.UserAuth;
import com.dev.security.repository.UserAuthRepository;
import org.apache.catalina.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
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
    @Autowired
    private RefreshTokenService refreshTokenService;
    @Autowired
    private AuthService authService;

    public LoginResponse handleLogin(LoginRequest loginRequest)
    {

        try {
            UsernamePasswordAuthenticationToken authObj = new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword());
            Authentication authRes = authenticationManager.authenticate(authObj);

            String jwtToken = jwtService.generateToken(authRes.getName());
            Date expireTime = jwtService.extractExpirationTime(jwtToken);

            UserAuth user = (UserAuth) authService.loadUserByUsername(authRes.getName());

            RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

            return new LoginResponse(
                    jwtToken,
                    expireTime,
                    refreshToken.getToken(),
                    refreshToken.getExpiresAt());
        }
        catch (Exception e)
        {
            throw new BadCredentialsException("Invalid credentials");
        }
    }

    public LoginResponse handleRefresh(String refreshToken)
    {
        RefreshToken refreshTokenObj = refreshTokenService.validateRefreshToken(refreshToken);
        UserAuth user = refreshTokenObj.getUser();

        String accessToken = jwtService.generateToken(user.getEmail());
        Date expiresIn = jwtService.extractExpirationTime(accessToken);

        return new LoginResponse(
                accessToken,
                expiresIn,
                refreshTokenObj.getToken(),
                refreshTokenObj.getExpiresAt()
        );
    }
}
