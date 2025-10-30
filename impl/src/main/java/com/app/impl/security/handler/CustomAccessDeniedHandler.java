package com.app.impl.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Map;

@Slf4j
@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void handle(
            HttpServletRequest request,
            HttpServletResponse response,
            AccessDeniedException e
    ) throws IOException
    {
        if (response.isCommitted()) {
            log.warn("Response already committed, skipping error handling");
            return;
        }

        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        PrintWriter responseWriter = response.getWriter();
        Map<String, Object> responseBody = Map.of(
                "error", "Forbidden source",
                "message", e.getMessage()
        );
        objectMapper.writeValue(responseWriter, responseBody);
        responseWriter.flush();

        log.atError()
                .setCause(e)
                .addKeyValue("method", request.getMethod())
                .addKeyValue("uri", request.getRequestURI())
                .log();
    }
}
