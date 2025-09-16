package com.app.impl.service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import com.app.impl.dto.tokenRefresh.TokenRefreshRequest;
import com.app.impl.dto.tokenValidation.TokenValidationRequest;
import com.app.impl.dto.tokenValidation.TokenValidationResponse;
import io.jsonwebtoken.JwtException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.app.impl.entity.RefreshToken;
import com.app.impl.exception.TokenExpiredException;
import com.app.impl.repository.RefreshTokenRepository;
import com.app.impl.enums.UserRole;
import com.app.impl.dto.auth.AuthResponse;
import com.app.impl.dto.auth.AuthRequest;
import com.app.impl.entity.User;
import com.app.impl.exception.UserAlreadyExistsException;
import com.app.impl.util.JwtUtil;
import com.app.impl.model.UserPrincipal;
import com.app.impl.repository.UserAuthRepository;
import com.app.impl.exception.UserPrincipalNotFoundException;

@Service
public class UserAuthService implements UserDetailsService {
    private final UserAuthRepository userAuthRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public UserAuthService(
            UserAuthRepository userAuthRepository,
            RefreshTokenRepository refreshTokenRepository,
            JwtUtil jwtUtil,
            PasswordEncoder passwordEncoder
    ) {
        this.userAuthRepository = userAuthRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtUtil = jwtUtil;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional(readOnly = true)
    @Override
    public UserPrincipal loadUserByUsername(String login) {
        return userAuthRepository.findByLogin(login)
                .map(user -> new UserPrincipal(
                        user.getLogin(),
                        user.getPasswordHash(),
                        user.getRoles()
                ))
                .orElseThrow(() -> new UserPrincipalNotFoundException(String.format("User with login %s was not found", login)));
    }

    @Transactional
    public void register(AuthRequest request) {
        final String login = request.login();

        if(userAuthRepository.findByLogin(login).isPresent()) {
            throw new UserAlreadyExistsException(login);
        }

        User user = User.builder()
                .login(login)
                .passwordHash(passwordEncoder.encode(request.password()))
                .roles(new ArrayList<>(List.of(UserRole.ROLE_USER)))
                .build();

        userAuthRepository.save(user);
    }

    @Transactional
    public AuthResponse login(AuthRequest request) {
        User user = userAuthRepository.findByLogin(request.login())
                .orElseThrow(() -> new UserPrincipalNotFoundException("User with login " + request.login() + " was not found"));

        if(!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            throw new BadCredentialsException("Incorrect password of user with login " + request.login());
        }

        UserPrincipal userPrincipal = loadUserByUsername(request.login());
        String accessToken = jwtUtil.generateAccessToken(userPrincipal);
        String refreshToken = jwtUtil.generateRefreshToken(userPrincipal);
        RefreshToken refreshTokenEntity = RefreshToken.builder()
                .tokenHash(passwordEncoder.encode(refreshToken))
                .user(user)
                .build();
        refreshTokenRepository.save(refreshTokenEntity);

        return new AuthResponse(accessToken, refreshToken);
    }

    @Transactional
    public AuthResponse refreshToken(TokenRefreshRequest request) {
        final String token = extractTokenFromHeader(request.tokenHeader());
        if(!jwtUtil.isRefreshToken(passwordEncoder.encode(token)))
            throw new JwtException("Given token is not refresh token! Could not process refresh!");

        if(!jwtUtil.isRefreshTokenValid(token))
            throw new TokenExpiredException("Refresh token has expired!");


        final String login = jwtUtil.extractUsername(token);
        User user = userAuthRepository.findByLogin(login)
                .orElseThrow(() -> new UserPrincipalNotFoundException("User with login " + login + " was not found"));

        UserPrincipal userPrincipal = loadUserByUsername(login);
        String accessToken = jwtUtil.generateAccessToken(userPrincipal);
        String refreshToken = jwtUtil.generateRefreshToken(userPrincipal);

        Optional<RefreshToken> oldRefreshToken = refreshTokenRepository.findByUser(user);
        oldRefreshToken.ifPresent(refreshTokenRepository::delete);
        RefreshToken refreshTokenEntity = RefreshToken.builder()
                .tokenHash(passwordEncoder.encode(refreshToken))
                .user(user)
                .build();
        refreshTokenRepository.save(refreshTokenEntity);

        return new AuthResponse(accessToken, refreshToken);
    }

    @Transactional(readOnly = true)
    public TokenValidationResponse validate(TokenValidationRequest request) {
        final String token = extractTokenFromHeader(request.tokenHeader());
        final String login = jwtUtil.extractUsername(token);
        UserPrincipal userPrincipal = loadUserByUsername(login);
        return new TokenValidationResponse(
                jwtUtil.isRefreshTokenValid(token),
                login
        );
    }

    public String extractTokenFromHeader(String header) {
        if(header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        else{
            throw new JwtException("Invalid token header");
        }
    }
}