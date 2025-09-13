package com.app.impl.dto.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record AuthRequest (
    @NotBlank(message = "Username should not be blank")
    @Size(min = 3, max = 100)
    String login,

    @NotBlank(message = "User password should not be blank")
    @Size(min = 6, max = 36)
    String password
) { }
