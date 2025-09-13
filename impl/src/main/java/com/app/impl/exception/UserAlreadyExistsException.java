package com.app.impl.exception;

public class UserAlreadyExistsException extends RuntimeException {
    public UserAlreadyExistsException(String login) {
        super(String.format("Username '%s' already exists!", login));
    }
}
