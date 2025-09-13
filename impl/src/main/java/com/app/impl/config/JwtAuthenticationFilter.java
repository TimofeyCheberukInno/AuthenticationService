package com.app.impl.config;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.app.impl.model.UserPrincipal;
import com.app.impl.service.UserAuthService;
import com.app.impl.util.JwtUtil;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final UserAuthService userAuthService;
    private final JwtUtil jwtUtil;

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

        filterChain.doFilter(request, response);
    }
}
