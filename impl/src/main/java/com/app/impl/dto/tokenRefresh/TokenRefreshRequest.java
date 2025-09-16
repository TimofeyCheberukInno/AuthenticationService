package com.app.impl.dto.tokenRefresh;

import jakarta.validation.constraints.NotBlank;

public record TokenRefreshRequest(
        @NotBlank(message = "token should not be blank")
        String tokenHeader
)
{ }
