package com.app.impl.dto.tokenValidation;

public record TokenValidationResponse(
    boolean valid,
    String login
) { }
