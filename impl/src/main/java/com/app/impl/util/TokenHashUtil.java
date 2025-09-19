package com.app.impl.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import org.springframework.stereotype.Component;

@Component
public class TokenHashUtil {
    public String hashToken(String token) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] bytes = token.getBytes(StandardCharsets.UTF_8);
        byte[] hash = md.digest(bytes);
        return Base64.getEncoder().encodeToString(hash);
    }

    public boolean matches(String token, String hash) throws NoSuchAlgorithmException {
        String tokenHash = hashToken(token);
        return tokenHash.equals(hash);
    }
}
