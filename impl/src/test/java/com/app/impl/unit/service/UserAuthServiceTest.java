package com.app.impl.unit.service;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.NoSuchAlgorithmException;
import java.util.Optional;

import com.app.impl.model.dto.tokenValidation.TokenValidationRequest;
import com.app.impl.model.dto.tokenValidation.TokenValidationResponse;
import io.jsonwebtoken.JwtException;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import com.app.impl.entity.RefreshToken;
import com.app.impl.exception.TokenExpiredException;
import com.app.impl.model.dto.auth.AuthResponse;
import com.app.impl.model.dto.tokenRefresh.TokenRefreshRequest;
import com.app.impl.exception.UserAlreadyExistsException;
import com.app.impl.model.dto.auth.AuthRequest;
import com.app.impl.entity.User;
import com.app.impl.enums.UserRole;
import com.app.impl.exception.UserPrincipalNotFoundException;
import com.app.impl.model.UserPrincipal;
import com.app.impl.repository.RefreshTokenRepository;
import com.app.impl.repository.UserAuthRepository;
import com.app.impl.service.UserAuthService;
import com.app.impl.util.JwtUtil;
import com.app.impl.util.TokenHashUtil;

@ExtendWith(MockitoExtension.class)
public class UserAuthServiceTest {
    @Mock
    UserAuthRepository userAuthRepository;

    @Mock
    RefreshTokenRepository refreshTokenRepository;

    @Mock
    JwtUtil jwtUtil;

    @Mock
    TokenHashUtil tokenHashUtil;

    @Mock
    EntityManager entityManager;

    @InjectMocks
    UserAuthService userAuthService;

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(userAuthService, "passwordEncoder", passwordEncoder);
        userAuthRepository.deleteAll();
        refreshTokenRepository.deleteAll();
    }

    @Nested
    @DisplayName("Tests for loadUserByUsername(String login)")
    class loadUserByUsernameTests {
        @Test
        @DisplayName("Successful return of user")
        void shouldReturnUser() {
            final String login = "username";
            final User user = User.builder()
                    .login(login)
                    .passwordHash(passwordEncoder.encode("password"))
                    .role(UserRole.ROLE_USER)
                    .build();
            final UserPrincipal userPrincipal = new UserPrincipal(
                    user.getLogin(),
                    user.getPasswordHash(),
                    user.getRole()
            );

            when(userAuthRepository.findByLogin(login)).thenReturn(Optional.of(user));
            assertEquals(userPrincipal, userAuthService.loadUserByUsername(login));

            verify(userAuthRepository, Mockito.times(1))
                    .findByLogin(login);
        }

        @Test
        @DisplayName("Returns UserPrincipalNotFoundException")
        void shouldReturnException() {
            final String login = "username";

            when(userAuthRepository.findByLogin(login)).thenReturn(Optional.empty());
            assertThatExceptionOfType(UserPrincipalNotFoundException.class)
                    .isThrownBy(() -> userAuthService.loadUserByUsername(login))
                    .withMessage(String.format("User with login %s was not found", login));

            verify(userAuthRepository, Mockito.times(1))
                    .findByLogin(login);
        }
    }

    @Nested
    @DisplayName("Tests for register(AuthRequest request)")
    class registerUserTests {
        final String login = "username";
        final String password = "123456";
        final AuthRequest authRequest = new AuthRequest(
                login,
                password
        );

        @Test
        @DisplayName("Successful register of user")
        void shouldRegisterUser() {
            when(userAuthRepository.findByLogin(login)).thenReturn(Optional.empty());

            userAuthService.register(authRequest);

            verify(userAuthRepository, Mockito.times(1))
                    .findByLogin(login);
        }

        @Test
        @DisplayName("Failed register of user")
        void shouldNotRegisterUser() {
            final User user = User.builder()
                    .login(login)
                    .passwordHash(passwordEncoder.encode(password))
                    .role(UserRole.ROLE_USER)
                    .build();

            when(userAuthRepository.findByLogin(login)).thenReturn(Optional.of(user));

            assertThatExceptionOfType(UserAlreadyExistsException.class)
                    .isThrownBy(() -> userAuthService.register(authRequest));

            verify(userAuthRepository, Mockito.times(1))
                    .findByLogin(login);
        }
    }

    @Nested
    @DisplayName("Tests for login(AuthRequest request)")
    class loginUserTests {
        final String login = "username";
        final String password = "123456";
        final AuthRequest authRequest = new AuthRequest(
                login,
                password
        );
        final User user = User.builder()
                .login(login)
                .passwordHash(passwordEncoder.encode(password))
                .role(UserRole.ROLE_USER)
                .build();
        final UserPrincipal userPrincipal = new UserPrincipal(
                user.getLogin(),
                user.getPasswordHash(),
                user.getRole()
        );

        @Test
        @DisplayName("Successful login of user")
        void shouldLoginUser() throws NoSuchAlgorithmException {
            when(userAuthRepository.findByLogin(login)).thenReturn(Optional.of(user));
            when(jwtUtil.generateAccessToken(userPrincipal)).thenReturn("accessToken");
            when(jwtUtil.generateRefreshToken(userPrincipal)).thenReturn("refreshToken");
            when(tokenHashUtil.hashToken("refreshToken")).thenReturn("refreshToken");

            AuthResponse actualResponse = userAuthService.login(authRequest);

            assertNotNull(actualResponse.accessToken());
            assertNotNull(actualResponse.refreshToken());

            verify(userAuthRepository, Mockito.times(2))
                    .findByLogin(login);
            verify(jwtUtil, Mockito.times(1))
                    .generateAccessToken(userPrincipal);
            verify(jwtUtil, Mockito.times(1))
                    .generateRefreshToken(userPrincipal);
            verify(tokenHashUtil, Mockito.times(1))
                    .hashToken("refreshToken");
            verify(refreshTokenRepository, Mockito.times(1))
                    .save(RefreshToken.builder()
                            .tokenHash("refreshToken")
                            .user(user)
                            .build());
        }

        @Test
        @DisplayName("Throws UserPrincipalNotFoundException")
        public void shouldThrowUserPrincipalNotFoundException() throws NoSuchAlgorithmException {
            when(userAuthRepository.findByLogin(login)).thenReturn(Optional.empty());

            assertThatExceptionOfType(UserPrincipalNotFoundException.class)
                    .isThrownBy(() -> userAuthService.login(authRequest))
                    .withMessage(String.format("User with login %s was not found", login));

            verify(userAuthRepository, Mockito.times(1))
                    .findByLogin(login);
            verify(jwtUtil, Mockito.never())
                    .generateAccessToken(Mockito.any());
            verify(jwtUtil, Mockito.never())
                    .generateRefreshToken(Mockito.any());
            verify(tokenHashUtil, Mockito.never())
                    .hashToken(Mockito.any());
            verify(refreshTokenRepository, Mockito.never())
                    .save(Mockito.any());
        }

        @Test
        @DisplayName("Throws BadCredentialsException")
        public void shouldThrowBadCredentialsException() throws NoSuchAlgorithmException {
            AuthRequest invalidAuthRequest = new AuthRequest(
                    login,
                    "invalid_password"
            );

            when(userAuthRepository.findByLogin(login)).thenReturn(Optional.of(user));

            assertThatExceptionOfType(BadCredentialsException.class)
                    .isThrownBy(() -> userAuthService.login(invalidAuthRequest))
                    .withMessage(String.format("Incorrect password of user with login %s", login));

            verify(userAuthRepository, Mockito.times(1))
                    .findByLogin(login);
            verify(jwtUtil, Mockito.never())
                    .generateAccessToken(Mockito.any());
            verify(jwtUtil, Mockito.never())
                    .generateRefreshToken(Mockito.any());
            verify(tokenHashUtil, Mockito.never())
                    .hashToken(Mockito.any());
            verify(refreshTokenRepository, Mockito.never())
                    .save(Mockito.any());
        }
    }

    @Nested
    @DisplayName("Tests for refreshToken(TokenRefreshRequest request)")
    class refreshTokenTests {
        final String login = "username";
        final String password = "123456";
        final User user = User.builder()
                .login(login)
                .passwordHash(passwordEncoder.encode(password))
                .role(UserRole.ROLE_USER)
                .build();
        final UserPrincipal userPrincipal = new UserPrincipal(
                user.getLogin(),
                user.getPasswordHash(),
                user.getRole()
        );
        final String token = "refreshToken";

        @Test
        @DisplayName("Successful token refresh")
        void shouldRefreshToken() throws NoSuchAlgorithmException {
            final String newAccessToken = "newAccessToken";
            final String newRefreshToken = "newRefreshToken";
            AuthResponse expectedResponse = new AuthResponse(
                    newAccessToken,
                    newRefreshToken
            );

            when(jwtUtil.isRefreshToken(token)).thenReturn(true);
            when(jwtUtil.isRefreshTokenValid(token)).thenReturn(true);
            when(jwtUtil.extractUsername(token)).thenReturn(login);
            when(userAuthRepository.findByLogin(login)).thenReturn(Optional.of(user));
            when(jwtUtil.generateAccessToken(userPrincipal)).thenReturn(newAccessToken);
            when(jwtUtil.generateRefreshToken(userPrincipal)).thenReturn(newRefreshToken);
            when(refreshTokenRepository.findByUser(user)).thenReturn(Optional.empty());
            when(tokenHashUtil.hashToken(newRefreshToken)).thenReturn(newRefreshToken);

            AuthResponse actualResponse = userAuthService.refreshToken(new TokenRefreshRequest("Bearer " + token));

            assertEquals(expectedResponse, actualResponse);

            verify(jwtUtil, Mockito.times(1))
                    .isRefreshToken(token);
            verify(jwtUtil, Mockito.times(1))
                    .isRefreshTokenValid(token);
            verify(jwtUtil, Mockito.times(1))
                    .extractUsername(token);
            verify(userAuthRepository, Mockito.times(2))
                    .findByLogin(login);
            verify(jwtUtil, Mockito.times(1))
                    .generateAccessToken(userPrincipal);
            verify(jwtUtil, Mockito.times(1))
                    .generateRefreshToken(userPrincipal);
            verify(refreshTokenRepository, Mockito.times(1))
                    .findByUser(user);
            verify(tokenHashUtil, Mockito.times(1))
                    .hashToken(newRefreshToken);
        }

        @Test
        @DisplayName("Throws JwtException")
        void shouldThrowJwtException() throws NoSuchAlgorithmException {
            when(jwtUtil.isRefreshToken(token)).thenReturn(false);

            assertThatExceptionOfType(JwtException.class)
                    .isThrownBy(() -> userAuthService.refreshToken(new TokenRefreshRequest("Bearer " + token)))
                    .withMessage("Given token is not refresh token! Could not process refresh!");

            verify(jwtUtil, Mockito.times(1))
                    .isRefreshToken(token);
            verify(jwtUtil, Mockito.never())
                    .isRefreshTokenValid(Mockito.any());
            verify(jwtUtil, Mockito.never())
                    .extractUsername(Mockito.any());
            verify(userAuthRepository, Mockito.never())
                    .findByLogin(Mockito.any());
            verify(jwtUtil, Mockito.never())
                    .generateAccessToken(Mockito.any());
            verify(jwtUtil, Mockito.never())
                    .generateRefreshToken(Mockito.any());
            verify(refreshTokenRepository, Mockito.never())
                    .findByUser(Mockito.any());
            verify(tokenHashUtil, Mockito.never())
                    .hashToken(Mockito.any());
        }

        @Test
        @DisplayName("Throws TokenExpiredException")
        void shouldThrowTokenExpiredException() throws NoSuchAlgorithmException {
            when(jwtUtil.isRefreshToken(token)).thenReturn(true);
            when(jwtUtil.isRefreshTokenValid(token)).thenReturn(false);

            assertThatExceptionOfType(TokenExpiredException.class)
                    .isThrownBy(() -> userAuthService.refreshToken(new TokenRefreshRequest("Bearer " + token)))
                    .withMessage("Refresh token has expired!");

            verify(jwtUtil, Mockito.times(1))
                    .isRefreshToken(token);
            verify(jwtUtil, Mockito.times(1))
                    .isRefreshTokenValid(token);
            verify(jwtUtil, Mockito.never())
                    .extractUsername(Mockito.any());
            verify(userAuthRepository, Mockito.never())
                    .findByLogin(Mockito.any());
            verify(jwtUtil, Mockito.never())
                    .generateAccessToken(Mockito.any());
            verify(jwtUtil, Mockito.never())
                    .generateRefreshToken(Mockito.any());
            verify(refreshTokenRepository, Mockito.never())
                    .findByUser(Mockito.any());
            verify(tokenHashUtil, Mockito.never())
                    .hashToken(Mockito.any());
        }

        @Test
        @DisplayName("Throws UserPrincipalNotFoundException")
        void shouldThrowUserPrincipalNotFoundException() throws NoSuchAlgorithmException {
            final String newAccessToken = "newAccessToken";
            final String newRefreshToken = "newRefreshToken";
            AuthResponse expectedResponse = new AuthResponse(
                    newAccessToken,
                    newRefreshToken
            );

            when(jwtUtil.isRefreshToken(token)).thenReturn(true);
            when(jwtUtil.isRefreshTokenValid(token)).thenReturn(true);
            when(jwtUtil.extractUsername(token)).thenReturn(login);
            when(userAuthRepository.findByLogin(login)).thenReturn(Optional.empty());

            assertThatExceptionOfType(UserPrincipalNotFoundException.class)
                    .isThrownBy(() -> userAuthService.refreshToken(new TokenRefreshRequest("Bearer " + token)))
                    .withMessage(String.format("User with login %s was not found", login));

            verify(jwtUtil, Mockito.times(1))
                    .isRefreshToken(token);
            verify(jwtUtil, Mockito.times(1))
                    .isRefreshTokenValid(token);
            verify(jwtUtil, Mockito.times(1))
                    .extractUsername(token);
            verify(userAuthRepository, Mockito.times(1))
                    .findByLogin(login);
            verify(jwtUtil, Mockito.never())
                    .generateAccessToken(Mockito.any());
            verify(jwtUtil, Mockito.never())
                    .generateRefreshToken(Mockito.any());
            verify(refreshTokenRepository, Mockito.never())
                    .findByUser(Mockito.any());
            verify(tokenHashUtil, Mockito.never())
                    .hashToken(Mockito.any());
        }
    }

    @Nested
    @DisplayName("Tests for validateRefreshToken(TokenValidationRequest request)")
    class ValidateRefreshTokenTests {
        final TokenValidationRequest request = new TokenValidationRequest("Bearer token");
        final String token = "token";
        final String login = "username";

        @Test
        @DisplayName("Successful positive validation")
        void shouldReturnPositiveValidation() throws NoSuchAlgorithmException {
            TokenValidationResponse expectedResponse = new TokenValidationResponse(
                    true,
                    login
            );

            when(jwtUtil.isRefreshToken(token)).thenReturn(true);
            when(jwtUtil.extractUsername(token)).thenReturn(login);
            when(jwtUtil.isRefreshTokenValid(token)).thenReturn(true);

            TokenValidationResponse actualResponse = userAuthService.validateRefreshToken(request);

            assertEquals(expectedResponse, actualResponse);

            verify(jwtUtil, Mockito.times(1))
                    .isRefreshToken(token);
            verify(jwtUtil, Mockito.times(1))
                    .extractUsername(token);
            verify(jwtUtil, Mockito.times(1))
                    .isRefreshTokenValid(token);
        }

        @Test
        @DisplayName("Successful negative validation")
        void shouldReturnNegativeValidation() throws NoSuchAlgorithmException {
            TokenValidationResponse expectedResponse = new TokenValidationResponse(
                    false,
                    login
            );

            when(jwtUtil.isRefreshToken(token)).thenReturn(true);
            when(jwtUtil.extractUsername(token)).thenReturn(login);
            when(jwtUtil.isRefreshTokenValid(token)).thenReturn(false);

            TokenValidationResponse actualResponse = userAuthService.validateRefreshToken(request);

            assertEquals(expectedResponse, actualResponse);

            verify(jwtUtil, Mockito.times(1))
                    .isRefreshToken(token);
            verify(jwtUtil, Mockito.times(1))
                    .extractUsername(token);
            verify(jwtUtil, Mockito.times(1))
                    .isRefreshTokenValid(token);
        }

        @Test
        @DisplayName("Throws JwtException")
        void shouldThrowJwtException() throws NoSuchAlgorithmException {
            when(jwtUtil.isRefreshToken(token)).thenReturn(false);

            assertThatExceptionOfType(JwtException.class)
                    .isThrownBy(() -> userAuthService.validateRefreshToken(request))
                    .withMessage("Given token is not refresh token! Could not process refresh!");

            verify(jwtUtil, Mockito.times(1))
                    .isRefreshToken(token);
            verify(jwtUtil, Mockito.never())
                    .extractUsername(Mockito.any());
            verify(jwtUtil, Mockito.never())
                    .isRefreshTokenValid(Mockito.any());
        }
    }

    @Nested
    @DisplayName("Tests for validateRefreshToken(TokenValidationRequest request)")
    class ValidateAccessTokenTests {
        final TokenValidationRequest request = new TokenValidationRequest("Bearer token");
        final String token = "token";
        final String login = "username";
        final String password = "123456";
        final User user = User.builder()
                .login(login)
                .passwordHash(passwordEncoder.encode(password))
                .role(UserRole.ROLE_USER)
                .build();
        final UserPrincipal userPrincipal = new UserPrincipal(
                user.getLogin(),
                user.getPasswordHash(),
                user.getRole()
        );

        @Test
        @DisplayName("Successful positive validation")
        void shouldReturnPositiveValidation() throws NoSuchAlgorithmException {
            TokenValidationResponse expectedResponse = new TokenValidationResponse(
                    true,
                    login
            );

            when(userAuthRepository.findByLogin(login)).thenReturn(Optional.of(user));
            when(jwtUtil.isRefreshToken(token)).thenReturn(false);
            when(jwtUtil.extractUsername(token)).thenReturn(login);
            when(jwtUtil.isAccessTokenValid(token, userPrincipal)).thenReturn(true);

            TokenValidationResponse actualResponse = userAuthService.validateAccessToken(request);

            assertEquals(expectedResponse, actualResponse);

            verify(userAuthRepository, Mockito.times(1))
                    .findByLogin(login);
            verify(jwtUtil, Mockito.times(1))
                    .isRefreshToken(token);
            verify(jwtUtil, Mockito.times(1))
                    .extractUsername(token);
            verify(jwtUtil, Mockito.times(1))
                    .isAccessTokenValid(token, userPrincipal);
        }

        @Test
        @DisplayName("Successful negative validation")
        void shouldReturnNegativeValidation() throws NoSuchAlgorithmException {
            TokenValidationResponse expectedResponse = new TokenValidationResponse(
                    false,
                    login
            );

            when(userAuthRepository.findByLogin(login)).thenReturn(Optional.of(user));
            when(jwtUtil.isRefreshToken(token)).thenReturn(false);
            when(jwtUtil.extractUsername(token)).thenReturn(login);
            when(jwtUtil.isAccessTokenValid(token, userPrincipal)).thenReturn(false);

            TokenValidationResponse actualResponse = userAuthService.validateAccessToken(request);

            assertEquals(expectedResponse, actualResponse);

            verify(userAuthRepository, Mockito.times(1))
                    .findByLogin(login);
            verify(jwtUtil, Mockito.times(1))
                    .isRefreshToken(token);
            verify(jwtUtil, Mockito.times(1))
                    .extractUsername(token);
            verify(jwtUtil, Mockito.times(1))
                    .isAccessTokenValid(token, userPrincipal);
        }

        @Test
        @DisplayName("Throws JwtException")
        void shouldThrowJwtException() throws NoSuchAlgorithmException {
            when(jwtUtil.isRefreshToken(token)).thenReturn(true);

            assertThatExceptionOfType(JwtException.class)
                    .isThrownBy(() -> userAuthService.validateAccessToken(request))
                    .withMessage("Given token is refresh token! Should be given with access token!");

            verify(userAuthRepository, Mockito.never())
                    .findByLogin(Mockito.any());
            verify(jwtUtil, Mockito.times(1))
                    .isRefreshToken(token);
            verify(jwtUtil, Mockito.never())
                    .extractUsername(Mockito.any());
            verify(jwtUtil, Mockito.never())
                    .isAccessTokenValid(Mockito.any(), Mockito.any());
        }
    }

    @Nested
    @DisplayName("Tests for extractTokenFromHeader")
    class ExtractTokenFromHeaderTests {
        @Test
        @DisplayName("Successful token extraction")
        void shouldExtractTokenFromHeader() {
            final String expectedToken = "token";
            final String header = "Bearer " + expectedToken;

            final String actualToken = userAuthService.extractTokenFromHeader(header);

            assertEquals(expectedToken, actualToken);
        }

        @Test
        @DisplayName("Throws JwtException because header is null")
        void shouldThrowJwtExceptionBecauseHeaderIsNull() {
            final String header = null;

            assertThatExceptionOfType(JwtException.class)
                    .isThrownBy(() -> userAuthService.extractTokenFromHeader(header))
                    .withMessage("Invalid token header");
        }

        @Test
        @DisplayName("Throws JwtException because header is invalid")
        void shouldThrowJwtExceptionBecauseHeaderIsInvalid() {
            final String header = "invalid header";

            assertThatExceptionOfType(JwtException.class)
                    .isThrownBy(() -> userAuthService.extractTokenFromHeader(header))
                    .withMessage("Invalid token header");
        }
    }
}