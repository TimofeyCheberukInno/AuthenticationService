package com.app.impl.enums;

public enum UserRole {
    ROLE_USER("USER"),
    ROLE_ADMIN("ADMIN");

    private final String value;

    UserRole(String value) {
        this.value = value;
    }

    public String getName() {
        return value;
    }
}
