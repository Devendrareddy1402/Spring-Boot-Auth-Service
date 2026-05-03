package com.dev.security.controller;

import com.dev.security.dto.LoginRequest;
import com.dev.security.dto.LoginResponse;
import com.dev.security.dto.RefreshRequest;
import com.dev.security.model.UserAuth;
import com.dev.security.service.AuthService;
import com.dev.security.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

/**
 * /auth/generateToken endpoint is for understanding the User login Design with Filter handles logic
 * i.e, follows Spring Security Framework Form Login logic.
 */

@RestController
@RequestMapping("/auth")
public class UserController {

    @Autowired
    private AuthService authService;
    @Autowired
    private UserService userService;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/register")
    public ResponseEntity<String> createUser(@RequestBody UserAuth userAuth)
    {
        userAuth.setPassword(passwordEncoder.encode(userAuth.getPassword()));
        authService.save(userAuth);
        return ResponseEntity.ok("User registered Successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> loginUser(@RequestBody LoginRequest loginRequest)
    {
        LoginResponse loginResponse = userService.handleLogin(loginRequest);
        return ResponseEntity.ok()
                .header("Authorization", "Bearer " + loginResponse.getAccessToken())
                .body(loginResponse);
    }

    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refreshToken(@RequestBody RefreshRequest refreshRequest)
    {
        LoginResponse loginResponse  = userService.handleRefresh(refreshRequest.getRefreshToken());
        return ResponseEntity.ok()
                .header("Authorization ", "Bearer "+ loginResponse.getAccessToken())
                .body(loginResponse);
    }
}
