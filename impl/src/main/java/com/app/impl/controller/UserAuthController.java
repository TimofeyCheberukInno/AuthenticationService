package com.app.impl.controller;

import java.security.NoSuchAlgorithmException;

import com.app.impl.model.dto.register.RegisterResponse;
import com.app.impl.service.UserAuthService;
import jakarta.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;

import com.app.impl.model.dto.auth.AuthResponse;
import com.app.impl.model.dto.tokenRefresh.TokenRefreshRequest;
import com.app.impl.model.dto.tokenValidation.TokenValidationRequest;
import com.app.impl.model.dto.tokenValidation.TokenValidationResponse;
import com.app.impl.model.dto.auth.AuthRequest;
import com.app.impl.exception.AuthenticationException;


@RestController
@RequestMapping("/auth")
public class UserAuthController {
    private final UserAuthService userAuthService;

    @Autowired
    public UserAuthController(UserAuthService userAuthService) {
        this.userAuthService = userAuthService;
    }

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@RequestBody @Valid AuthRequest request) throws AuthenticationException {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(userAuthService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody @Valid AuthRequest request) throws AuthenticationException, NoSuchAlgorithmException {
        return ResponseEntity.status(HttpStatus.OK)
                .body(userAuthService.login(request));
    }

    @PutMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@RequestBody @Valid TokenRefreshRequest request) throws AuthenticationException, NoSuchAlgorithmException {
        return ResponseEntity.status(HttpStatus.OK)
                .body(userAuthService.refreshToken(request));
    }

    @PostMapping("/validateAccessToken")
    public ResponseEntity<TokenValidationResponse> validateAccessToken(@RequestBody @Valid TokenValidationRequest request) throws AuthenticationException, NoSuchAlgorithmException {
        return ResponseEntity.status(HttpStatus.OK)
                .body(userAuthService.validateAccessToken(request));
    }

    @PostMapping("/validateRefreshToken")
    public ResponseEntity<TokenValidationResponse> validateRefreshToken(@RequestBody @Valid TokenValidationRequest request) throws AuthenticationException, NoSuchAlgorithmException {
        return ResponseEntity.status(HttpStatus.OK)
                .body(userAuthService.validateRefreshToken(request));
    }
}
