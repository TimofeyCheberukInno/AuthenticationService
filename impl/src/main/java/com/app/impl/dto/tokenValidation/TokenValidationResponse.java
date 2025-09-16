package com.app.impl.dto.tokenValidation;

import jakarta.validation.constraints.NotBlank;

public record TokenValidationResponse(
    boolean valid,
    @NotBlank
    String login
) { }
