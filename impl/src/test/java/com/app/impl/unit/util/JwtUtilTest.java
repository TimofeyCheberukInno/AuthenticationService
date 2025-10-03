package com.app.impl.unit.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import com.app.impl.enums.UserRole;
import com.app.impl.model.UserPrincipal;
import com.app.impl.repository.RefreshTokenRepository;
import com.app.impl.util.JwtUtil;
import com.app.impl.util.TokenHashUtil;

@ExtendWith(MockitoExtension.class)
public class JwtUtilTest {
    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private TokenHashUtil tokenHashUtil;

    @InjectMocks
    private JwtUtil jwtUtil;

    private UserPrincipal userPrincipal;

    @BeforeEach
    void beforeAll() {
        ReflectionTestUtils.setField(jwtUtil, "secretKey", "d2VyaW5zd2VpbnN1cGVyd2FzZ2Vpc2VjcmV0a2V5Zm9yand0YW5kc3ByaW5n");
        ReflectionTestUtils.setField(jwtUtil, "accessTokenExpiration", 1800000);
        ReflectionTestUtils.setField(jwtUtil, "refreshTokenExpiration", 604800000);

        userPrincipal = new UserPrincipal(
                "user",
                "12345",
                UserRole.ROLE_USER
        );
    }

    @Nested
    @DisplayName("Tests for generateAccessToken(UserPrincipal userPrincipal)")
    class generateAccessTokenTests {
        @Test
        @DisplayName("Test that token is not blank")
        void shouldTestThatTokenIsNotBlank() {
            assertFalse(jwtUtil.generateAccessToken(userPrincipal).isBlank());
        }
    }

    @Nested
    @DisplayName("Tests for generateRefreshToken(UserPrincipal userPrincipal)")
    class generateRefreshTokenTests {
        @Test
        @DisplayName("Test that token is not blank")
        void shouldTestThatTokenIsNotBlank() {
            assertFalse(jwtUtil.generateRefreshToken(userPrincipal).isBlank());
        }
    }

    @Nested
    @DisplayName("Tests for extractUsername(String token)")
    class generateAccessToken {
        @Test
        @DisplayName("Test that username extracts from token")
        void shouldTestThatUsernameExtractsFromToken() {
            String token = jwtUtil.generateAccessToken(userPrincipal);
            assertEquals(userPrincipal.getUsername(), jwtUtil.extractUsername(token));
        }
    }

    @Nested
    @DisplayName("Tests for tokens expiration methods")
    class isTokenExpiredTests {
        @Test
        @DisplayName("Check that token is not expired right after creation")
        void shouldTestThatTokenIsNotExpiredAfterCreation() {
            String token = jwtUtil.generateAccessToken(userPrincipal);
            assertFalse(jwtUtil.isTokenExpired(token));
        }
    }
}
