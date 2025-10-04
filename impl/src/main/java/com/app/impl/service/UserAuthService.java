package com.app.impl.service;

import java.security.NoSuchAlgorithmException;

import com.app.impl.model.dto.auth.AuthRequest;
import com.app.impl.model.dto.auth.AuthResponse;
import com.app.impl.model.dto.tokenValidation.TokenValidationResponse;
import com.app.impl.model.dto.register.RegisterResponse;
import com.app.impl.model.dto.tokenRefresh.TokenRefreshRequest;
import com.app.impl.model.dto.tokenValidation.TokenValidationRequest;

public interface UserAuthService {
    RegisterResponse register(AuthRequest request);

    AuthResponse login(AuthRequest request) throws NoSuchAlgorithmException;

    AuthResponse refreshToken(TokenRefreshRequest request) throws NoSuchAlgorithmException;

    TokenValidationResponse validateRefreshToken(TokenValidationRequest request) throws NoSuchAlgorithmException;

    TokenValidationResponse validateAccessToken(TokenValidationRequest request) throws NoSuchAlgorithmException;

    String extractTokenFromHeader(String header);
}
