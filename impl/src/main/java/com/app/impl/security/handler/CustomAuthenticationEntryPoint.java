package com.app.impl.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Map;

@Slf4j
@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException e
    ) throws IOException
    {
        SecurityContextHolder.clearContext();

        if (response.isCommitted()) {
            log.warn("Response already committed, skipping error handling");
            return;
        }

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.setHeader("WWW-Authenticate", "Bearer realm=\"api\", error=\"invalid_token\"");

        PrintWriter responseWriter = response.getWriter();
        Map<String, Object> responseBody = Map.of(
                "error", "Authentication failed",
                "message", e.getMessage() == null ? "" : e.getMessage()
        );
        objectMapper.writeValue(responseWriter, responseBody);
        responseWriter.flush();

        log.atError()
                .setCause(e)
                .log();
    }
}
