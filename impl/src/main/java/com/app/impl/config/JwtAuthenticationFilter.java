package com.app.impl.config;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.app.impl.exception.AuthenticationException;
import com.app.impl.exception.TokenExpiredException;
import com.app.impl.model.UserPrincipal;
import com.app.impl.service.UserAuthService;
import com.app.impl.util.JwtUtil;

@Slf4j
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final UserAuthService userAuthService;
    private final JwtUtil jwtUtil;

    @Autowired
    public JwtAuthenticationFilter(
            UserAuthService userAuthService,
            JwtUtil jwtUtil
    ) {
        this.userAuthService = userAuthService;
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        final String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            final String jwt = header.substring(7);
            final String username = jwtUtil.extractUsername(jwt);
            if(username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserPrincipal userPrincipal = userAuthService.loadUserByUsername(username);

                if(jwtUtil.isAccessTokenValid(jwt, userPrincipal)) {
                    UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                            userPrincipal,
                            null,
                            userPrincipal.getAuthorities()
                    );
                    SecurityContextHolder.getContext().setAuthentication(token);
                }
            }
        } catch (AuthenticationException | TokenExpiredException e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write(e.getMessage());
            log.error(e.getMessage());
        }

        filterChain.doFilter(request, response);
    }
}
