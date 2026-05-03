package com.dev.security.config;

import com.dev.security.entrypoint.JWTAuthEntryPoint;
import com.dev.security.filter.JWTValidateFilter;
import com.dev.security.provider.JWTValidationProvider;
import com.dev.security.service.JWTService;
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

import java.util.Arrays;


@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final UserDetailsService userDetailsService;
    private final JWTService jwtService;
    private final JWTAuthEntryPoint jwtAuthEntrypoint;


    public SecurityConfig(JWTService jwtService, UserDetailsService userDetailsService, JWTAuthEntryPoint jwtAuthEntrypoint) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
        this.jwtAuthEntrypoint = jwtAuthEntrypoint;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    JWTValidationProvider jwtValidationProvider() {
        JWTValidationProvider jwtValidationProvider = new JWTValidationProvider(jwtService, userDetailsService);
        return jwtValidationProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(Arrays.asList(daoAuthenticationProvider(), jwtValidationProvider()));
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   AuthenticationManager authenticationManager,
                                                   JWTService jwtService) throws Exception {
        JWTValidateFilter jwtValidFilter = new JWTValidateFilter(authenticationManager, jwtService);

        http.authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/**").permitAll()
                        .anyRequest().authenticated()
                )
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(jwtAuthEntrypoint)
                )
                .csrf(csrf -> csrf.disable())
                .addFilterBefore(jwtValidFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();

        // For understanding the User login design with Filter logic.
/*
            JWTAuthFilter jwtAuthFilter = new JWTAuthFilter(authenticationManager, jwtUtil);
            http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/auth/register", "/auth/generateToken").permitAll()
                        .anyRequest().authenticated()
                )
                .csrf(csrf-> csrf.disable())
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
               .addFilterAfter(jwtValidFilter, JWTAuthFilter.class);
*/
    }
}
