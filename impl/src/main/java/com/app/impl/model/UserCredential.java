package com.app.impl.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record UserCredential(
        @NotBlank
        @Size(min = 3, max = 100)
        String login,

        @NotBlank
        @Size(min = 6, max = 255)
        String password
)
{ }