package com.dev.security.service;

import com.dev.security.model.RefreshToken;
import com.dev.security.model.UserAuth;
import com.dev.security.repository.RefreshTokenRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.UUID;

@Service
public class RefreshTokenService {

    @Value("${jwt.refresh.token.timeout}")
    private long refreshTimeout;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;


    @Transactional
    public RefreshToken createRefreshToken(UserAuth user)
    {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setUser(user);
        refreshToken.setExpiresAt(new Date(System.currentTimeMillis() + refreshTimeout));
        refreshToken.setRevoked(false);

        return refreshTokenRepository.save(refreshToken);
    }

    public RefreshToken validateRefreshToken(String token)
    {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new BadCredentialsException("Invalid refresh token"));


        if (refreshToken.isRevoked())
        {
            throw new BadCredentialsException("Refresh token has been revoked");
        }

        if (refreshToken.getExpiresAt().before(new Date()))
        {
            refreshTokenRepository.delete(refreshToken);
            throw new CredentialsExpiredException("Refresh token has expired ");
        }

        return refreshToken;
    }

    @Transactional
    public void revokeToken(String token)
    {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(token).orElseThrow(()-> new BadCredentialsException("Invalid refresh token"));
        refreshToken.setRevoked(true);
        refreshTokenRepository.save(refreshToken);
    }

}
