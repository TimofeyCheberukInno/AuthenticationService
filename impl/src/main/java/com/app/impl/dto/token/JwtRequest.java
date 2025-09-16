package com.app.impl.dto.token;

import jakarta.validation.constraints.NotBlank;

public record JwtRequest (
        @NotBlank(message = "token should not be blank")
        String token
)
{ }
