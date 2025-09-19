package com.app.impl.model.dto.auth;

public record AuthResponse(
    String accessToken,
    String refreshToken
) { }
