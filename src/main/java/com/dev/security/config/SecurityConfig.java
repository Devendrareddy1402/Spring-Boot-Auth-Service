package com.dev.security.config;

import com.dev.security.filter.JWTAuthFilter;
import com.dev.security.filter.JWTValidateFilter;
import com.dev.security.util.JWTUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import provider.JWTValidationProvider;

import java.util.Arrays;


@Configuration
@EnableWebSecurity
public class SecurityConfig {

    public UserDetailsService userDetailsService;
    public JWTUtil jwtUtil;

    public SecurityConfig(JWTUtil jwtUtil, UserDetailsService userDetailsService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider()
    {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    JWTValidationProvider jwtValidationProvider()
    {
        JWTValidationProvider jwtValidationProvider = new JWTValidationProvider(jwtUtil, userDetailsService);
        return jwtValidationProvider;
    }

    @Bean
    public AuthenticationManager authManager() {
        return new ProviderManager(Arrays.asList(daoAuthenticationProvider(), jwtValidationProvider()));
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager, JWTUtil jwtUtil) throws Exception {
        JWTAuthFilter jwtAuthFilter = new JWTAuthFilter(authenticationManager, jwtUtil);
        JWTValidateFilter jwtValidFilter = new JWTValidateFilter(authenticationManager, jwtUtil);
        http.authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/register","auth/generateToken", "/auth/login").permitAll()
                        .anyRequest().authenticated()
                )
                .csrf(csrf -> csrf.disable())
                .addFilterBefore(jwtValidFilter, UsernamePasswordAuthenticationFilter.class);


        // For understanding the User login design with Filter logic.
//        http.authorizeHttpRequests(auth -> auth
//                .requestMatchers("/auth/register", "/auth/generateToken").permitAll()
//                        .anyRequest().authenticated()
//                )
//                .csrf(csrf-> csrf.disable())
//                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
//                .addFilterAfter(jwtValidFilter, JWTAuthFilter.class);

        return http.build();
    }
}
