package com.app.impl.util;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.function.Function;

import com.app.impl.exception.TokenExpiredException;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.app.impl.exception.AuthenticationException;
import com.app.impl.model.UserPrincipal;

@Component
public class JwtUtil {
    @Value("${jwt.access-token.expiration}")
    private long accessTokenExpiration;

    @Value("${jwt.refresh-token.expiration}")
    private long refreshTokenExpiration;

    private final String secretKey;

    public JwtUtil(@Value("${jwt.secret-key}") String secretKey) {
        this.secretKey = secretKey;
    }

    public String generateAccessToken(UserPrincipal userPrincipal) {
        return Jwts.builder()
                .setClaims(new HashMap<>())
                .setSubject(userPrincipal.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + accessTokenExpiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateRefreshToken(UserPrincipal userPrincipal) {
        return Jwts.builder()
                .setClaims(new HashMap<>())
                .setSubject(userPrincipal.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + refreshTokenExpiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public boolean validateAccessToken(String token, UserPrincipal userPrincipal) {
        return !isTokenExpired(token) && userPrincipal.getUsername().equals(extractUsername(token));
    }

    public boolean validateRefreshToken(String token) {
        return !isTokenExpired(token);
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        try {
            return Jwts
                    .parserBuilder()
                    .setSigningKey(getSignInKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (SignatureException e) {
            throw new AuthenticationException("Invalid token signature" + e.getMessage());
        } catch (MalformedJwtException e) {
            throw new AuthenticationException("Invalid token building: " + e.getMessage());
        } catch (ExpiredJwtException e) {
            throw new TokenExpiredException("Token is expired: " + e.getMessage());
        }
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
