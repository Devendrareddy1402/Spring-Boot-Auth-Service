package com.dev.security.controller;

import com.dev.security.dao.LoginRequest;
import com.dev.security.model.UserAuth;
import com.dev.security.service.UserAuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/auth")
public class UserController {

    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private UserAuthService userAuthService;

    @PostMapping("/register")
    public ResponseEntity<String> createUser(@RequestBody UserAuth userAuth)
    {
        userAuth.setPassword(passwordEncoder.encode(userAuth.getPassword()));
        userAuthService.save(userAuth);

        return ResponseEntity.ok("User registered Successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<String> loginUser(@RequestBody LoginRequest loginRequest)
    {

        return ResponseEntity.ok("Successfully Login");
    }

}
