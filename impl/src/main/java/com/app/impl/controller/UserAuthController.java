package com.app.impl.controller;

import jakarta.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;

import com.app.impl.dto.auth.AuthResponse;
import com.app.impl.dto.tokenRefresh.TokenRefreshRequest;
import com.app.impl.dto.tokenValidation.TokenValidationRequest;
import com.app.impl.dto.tokenValidation.TokenValidationResponse;
import com.app.impl.dto.auth.AuthRequest;
import com.app.impl.exception.AuthenticationException;
import com.app.impl.service.UserAuthService;

@RestController
@RequestMapping("/auth")
public class UserAuthController {
    private final UserAuthService userAuthService;

    @Autowired
    public UserAuthController(UserAuthService userAuthService) {
        this.userAuthService = userAuthService;
    }

    @PostMapping("/register")
    public ResponseEntity<Void> register(@RequestBody @Valid AuthRequest request) throws AuthenticationException {
        userAuthService.register(request);
        return ResponseEntity.status(HttpStatus.OK)
                .build();
    }

    @RequestMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody @Valid AuthRequest request) throws AuthenticationException {
        return ResponseEntity.status(HttpStatus.OK)
                .body(userAuthService.login(request));
    }

    @PutMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@RequestBody @Valid TokenRefreshRequest request) throws AuthenticationException {
        return ResponseEntity.status(HttpStatus.OK)
                .body(userAuthService.refreshToken(request));
    }

    @GetMapping("/validate")
    public ResponseEntity<TokenValidationResponse> validate(@RequestBody @Valid TokenValidationRequest request) throws AuthenticationException {
        return ResponseEntity.status(HttpStatus.OK)
                .body(userAuthService.validate(request));
    }
}
