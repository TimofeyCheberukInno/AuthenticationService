package com.app.impl.dto.auth;

public record AuthResponse(
    String accessToken,
    String refreshToken
) { }
