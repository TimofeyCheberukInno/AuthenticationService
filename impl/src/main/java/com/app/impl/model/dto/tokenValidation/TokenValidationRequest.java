package com.app.impl.model.dto.tokenValidation;

import jakarta.validation.constraints.NotBlank;

public record TokenValidationRequest (
    @NotBlank
    String tokenHeader
) { }
