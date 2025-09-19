package com.app.impl.model.dto.tokenValidation;

public record TokenValidationResponse(
    boolean valid,
    String login
) { }
