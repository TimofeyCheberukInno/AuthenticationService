package com.app.impl.exception;

public class UserNotFoundException extends RuntimeException {
    public UserNotFoundException(String login) {
        super(String.format("Uses with login %s was not found", login));
    }
}
