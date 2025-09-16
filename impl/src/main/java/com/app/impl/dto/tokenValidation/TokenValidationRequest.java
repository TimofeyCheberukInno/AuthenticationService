package com.app.impl.dto.tokenValidation;

import jakarta.validation.constraints.NotBlank;

public record TokenValidationRequest (
    @NotBlank
    String tokenHeader
) { }
