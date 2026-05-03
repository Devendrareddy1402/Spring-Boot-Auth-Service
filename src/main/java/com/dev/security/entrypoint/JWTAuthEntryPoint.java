package com.dev.security.entrypoint;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class JWTAuthEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        Exception originalException = (Exception) request.getAttribute("exception");

        String message;
        int status;

        if (originalException == null)
        {
            message = "Unauthorized";
            status = HttpServletResponse.SC_UNAUTHORIZED;
        }
        else if (originalException instanceof CredentialsExpiredException)
        {
            message = "Token expired";
            status = HttpServletResponse.SC_UNAUTHORIZED;
        }
        else
        {
            message = originalException.getMessage();
            status = HttpServletResponse.SC_UNAUTHORIZED;
        }

        response.setContentType("application/json");
        response.setStatus(status);
        response.getWriter().write("{\"error\": " + status + ", \"message\": \"" + message + "\"}");

    }
}
