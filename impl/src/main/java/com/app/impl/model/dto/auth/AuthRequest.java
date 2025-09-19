package com.app.impl.model.dto.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record AuthRequest (
    @NotBlank(message = "Username should not be blank")
    @Size(min = 3, max = 100, message = "Login length should be between 3 and 100")
    String login,

    @NotBlank(message = "User password should not be blank")
    @Size(min = 6, max = 36, message = "Login length should be between 6 and 36")
    String password
) { }
