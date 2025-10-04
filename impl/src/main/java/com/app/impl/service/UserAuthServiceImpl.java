package com.app.impl.service;

import java.security.NoSuchAlgorithmException;
import java.util.Optional;

import jakarta.persistence.EntityManager;

import io.jsonwebtoken.JwtException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.app.impl.model.dto.tokenRefresh.TokenRefreshRequest;
import com.app.impl.util.TokenHashUtil;
import com.app.impl.model.dto.tokenValidation.TokenValidationRequest;
import com.app.impl.model.dto.register.RegisterResponse;
import com.app.impl.model.dto.tokenValidation.TokenValidationResponse;
import com.app.impl.entity.RefreshToken;
import com.app.impl.exception.TokenExpiredException;
import com.app.impl.repository.RefreshTokenRepository;
import com.app.impl.enums.UserRole;
import com.app.impl.model.dto.auth.AuthResponse;
import com.app.impl.model.dto.auth.AuthRequest;
import com.app.impl.entity.User;
import com.app.impl.exception.UserAlreadyExistsException;
import com.app.impl.util.JwtUtil;
import com.app.impl.model.UserPrincipal;
import com.app.impl.repository.UserAuthRepository;
import com.app.impl.exception.UserPrincipalNotFoundException;

@Service
public class UserAuthServiceImpl implements UserDetailsService, UserAuthService {
    private final UserAuthRepository userAuthRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;
    private final TokenHashUtil tokenHashUtil;
    private final EntityManager entityManager;

    @Autowired
    public UserAuthServiceImpl(
            UserAuthRepository userAuthRepository,
            RefreshTokenRepository refreshTokenRepository,
            JwtUtil jwtUtil,
            PasswordEncoder passwordEncoder,
            TokenHashUtil tokenHashUtil,
            EntityManager entityManager
    ) {
        this.userAuthRepository = userAuthRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtUtil = jwtUtil;
        this.passwordEncoder = passwordEncoder;
        this.tokenHashUtil = tokenHashUtil;
        this.entityManager = entityManager;
    }

    @Transactional(readOnly = true)
    @Override
    public UserPrincipal loadUserByUsername(String login) {
        return userAuthRepository.findByLogin(login)
                .map(user -> new UserPrincipal(
                        user.getLogin(),
                        user.getPasswordHash(),
                        user.getRole()
                ))
                .orElseThrow(() -> new UserPrincipalNotFoundException(String.format("User with login %s was not found", login)));
    }

    @Transactional
    @Override
    public RegisterResponse register(AuthRequest request) {
        final String login = request.login();

        if(userAuthRepository.findByLogin(login).isPresent()) {
            throw new UserAlreadyExistsException(login);
        }

        User user = User.builder()
                .login(login)
                .passwordHash(passwordEncoder.encode(request.password()))
                .role(UserRole.ROLE_USER)
                .build();

        User savedUser = userAuthRepository.save(user);
        RegisterResponse registerResponse = new RegisterResponse(
                savedUser.getId(),
                savedUser.getLogin()
        );
        return registerResponse;
    }

    @Transactional
    @Override
    public AuthResponse login(AuthRequest request) throws NoSuchAlgorithmException {
        User user = userAuthRepository.findByLogin(request.login())
                .orElseThrow(() -> new UserPrincipalNotFoundException("User with login " + request.login() + " was not found"));

        if(!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            throw new BadCredentialsException("Incorrect password of user with login " + request.login());
        }

        UserPrincipal userPrincipal = loadUserByUsername(request.login());
        String accessToken = jwtUtil.generateAccessToken(userPrincipal);
        String refreshToken = jwtUtil.generateRefreshToken(userPrincipal);

        RefreshToken refreshTokenEntity = RefreshToken.builder()
                .tokenHash(tokenHashUtil.hashToken(refreshToken))
                .user(user)
                .build();

        Optional<RefreshToken> oldRefreshToken = refreshTokenRepository.findByUser(user);
        oldRefreshToken.ifPresent(refreshTokenRepository::delete);
        // Метод flush() заставляет JPA синхронизировать состояние Persistence Context
        // с базой данных, отправляя все накопленные SQL-запросы
        // (в данном случае DELETE) в базу данных немедленно.
        entityManager.flush();
        refreshTokenRepository.save(refreshTokenEntity);

        return new AuthResponse(accessToken, refreshToken);
    }

    @Transactional
    @Override
    public AuthResponse refreshToken(TokenRefreshRequest request) throws NoSuchAlgorithmException {
        final String token = extractTokenFromHeader(request.tokenHeader());
        if(!jwtUtil.isRefreshToken(token))
            throw new JwtException("Given token is not refresh token! Could not process refresh!");

        if(!jwtUtil.isRefreshTokenValid(token))
            throw new TokenExpiredException("Refresh token has expired!");


        final String login = jwtUtil.extractUsername(token);
        User user = userAuthRepository.findByLogin(login)
                .orElseThrow(() -> new UserPrincipalNotFoundException("User with login " + login + " was not found"));

        UserPrincipal userPrincipal = loadUserByUsername(login);
        String accessToken = jwtUtil.generateAccessToken(userPrincipal);
        String refreshToken = jwtUtil.generateRefreshToken(userPrincipal);

        RefreshToken refreshTokenEntity = RefreshToken.builder()
                .tokenHash(tokenHashUtil.hashToken(refreshToken))
                .user(user)
                .build();

        Optional<RefreshToken> oldRefreshToken = refreshTokenRepository.findByUser(user);
        oldRefreshToken.ifPresent(refreshTokenRepository::delete);
        // Метод flush() заставляет JPA синхронизировать состояние Persistence Context
        // с базой данных, отправляя все накопленные SQL-запросы
        // (в данном случае DELETE) в базу данных немедленно.
        entityManager.flush();
        refreshTokenRepository.save(refreshTokenEntity);

        return new AuthResponse(accessToken, refreshToken);
    }

    @Transactional(readOnly = true)
    @Override
    public TokenValidationResponse validateRefreshToken(TokenValidationRequest request) throws NoSuchAlgorithmException {
        final String token = extractTokenFromHeader(request.tokenHeader());
        if(!jwtUtil.isRefreshToken(token))
            throw new JwtException("Given token is not refresh token! Could not process refresh!");

        final String login = jwtUtil.extractUsername(token);
        return new TokenValidationResponse(
                jwtUtil.isRefreshTokenValid(token),
                login
        );
    }

    @Transactional(readOnly = true)
    @Override
    public TokenValidationResponse validateAccessToken(TokenValidationRequest request) throws NoSuchAlgorithmException {
        final String token = extractTokenFromHeader(request.tokenHeader());
        if(jwtUtil.isRefreshToken(token))
            throw new JwtException("Given token is refresh token! Should be given with access token!");

        final String login = jwtUtil.extractUsername(token);
        final UserPrincipal userPrincipal = loadUserByUsername(login);
        return new TokenValidationResponse(
                jwtUtil.isAccessTokenValid(token, userPrincipal),
                login
        );
    }

    @Override
    public String extractTokenFromHeader(String header) {
        if(header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        else{
            throw new JwtException("Invalid token header");
        }
    }
}