package com.app.impl.exception;

public class UserPrincipalNotFoundException extends RuntimeException {
    public UserPrincipalNotFoundException(String message) {
        super(message);
    }
}
