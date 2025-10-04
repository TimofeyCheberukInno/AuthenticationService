package com.app.impl.integration;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.app.impl.service.UserAuthService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.MediaType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import com.app.impl.model.UserPrincipal;
import com.app.impl.model.dto.tokenValidation.TokenValidationRequest;
import com.app.impl.model.dto.tokenValidation.TokenValidationResponse;
import com.app.impl.entity.User;
import com.app.impl.enums.UserRole;
import com.app.impl.model.dto.auth.AuthResponse;
import com.app.impl.model.dto.tokenRefresh.TokenRefreshRequest;
import com.app.impl.util.JwtUtil;
import com.app.impl.util.TokenHashUtil;
import com.app.impl.model.dto.auth.AuthRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.app.impl.repository.UserAuthRepository;
import com.app.impl.repository.RefreshTokenRepository;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@Testcontainers
@AutoConfigureMockMvc
public class UserAuthControllerIT {
    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserAuthService userAuthService;

    @Autowired
    private UserAuthRepository userAuthRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    JwtUtil jwtUtil;

    JwtUtil jwtUtilSpy;

    @Autowired
    TokenHashUtil tokenHashUtil;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    ObjectMapper objectMapper;

    @Container
    @ServiceConnection
    private static PostgreSQLContainer<?> postgreSQLContainer
            = new PostgreSQLContainer<>(DockerImageName.parse("postgres:17-alpine"));

    @BeforeEach
    public void setup() {
        jwtUtilSpy = Mockito.spy(jwtUtil);

        refreshTokenRepository.deleteAll();
        userAuthRepository.deleteAll();
    }

    @Nested
    @DisplayName("Tests for /register")
    class RegisterTests {
        final String login = "username";
        final String password = "123456";

        @Test
        @DisplayName("return 201 status")
        void shouldSuccessfullyRegisterUser() throws Exception {
            AuthRequest authRequest = new AuthRequest(
                    login,
                    password
            );

            mockMvc.perform(post("/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(authRequest)))
                    .andExpect(status().isCreated());
        }

        @Test
        @DisplayName("return 400 status because auth request is invalid")
        void shouldReturnBadRequestStatus() throws Exception {
            AuthRequest authRequest = new AuthRequest(
                    null,
                    null
            );

            mockMvc.perform(post("/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(authRequest)))
                    .andExpect(status().isBadRequest());
        }
    }

    @Nested
    @DisplayName("Tests for /login")
    class LoginTests {
        final String login = "username";
        final String password = "123456";

        @Test
        @DisplayName("return 200 status")
        void shouldSuccessfullyLoginUser() throws Exception {
            AuthRequest authRequest = new AuthRequest(
                    login,
                    password
            );

            User user = User.builder()
                    .login(login)
                    .passwordHash(passwordEncoder.encode(password))
                    .role(UserRole.ROLE_USER)
                    .build();
            userAuthRepository.save(user);

            mockMvc.perform(post("/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(authRequest)))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("return 400 status because auth request is invalid")
        void shouldReturnBadRequestStatus() throws Exception {
            AuthRequest authRequest = new AuthRequest(
                    null,
                    null
            );

            mockMvc.perform(post("/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(authRequest)))
                    .andExpect(status().isBadRequest());
        }
    }

    @Nested
    @DisplayName("Tests for /refresh")
    class RefreshTests {
        final String login = "username";
        final String password = "123456";

        @Test
        @DisplayName("return 200 status")
        void shouldSuccessfullyRefreshUser() throws Exception {
            AuthRequest authRequest = new AuthRequest(
                    login,
                    password
            );
            userAuthService.register(authRequest);
            AuthResponse authResponse = userAuthService.login(authRequest);

            final String tokenHeader = "Bearer " + authResponse.refreshToken();
            TokenRefreshRequest request = new TokenRefreshRequest(tokenHeader);

            mockMvc.perform(put("/auth/refresh")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName("return 400 status because token refresh request is invalid")
        void shouldReturnBadRequestStatus() throws Exception {
            TokenRefreshRequest request = new TokenRefreshRequest(
                    "invalid"
            );

            mockMvc.perform(put("/auth/refresh")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isBadRequest());
        }
    }

    @Nested
    @DisplayName("Tests for /validateAccessToken")
    class ValidateAccessTokenTests {
        final String login = "username";
        final String password = "123456";

        @Test
        @DisplayName("return 200 status and positive validation result")
        void shouldPositivelyValidateAccessToken() throws Exception {
            AuthRequest authRequest = new AuthRequest(
                    login,
                    password
            );
            userAuthService.register(authRequest);
            AuthResponse authResponse = userAuthService.login(authRequest);
            TokenValidationRequest tokenValidationRequest = new TokenValidationRequest("Bearer " + authResponse.accessToken());

            MvcResult result = mockMvc.perform(post("/auth/validateAccessToken")
                            .contentType(MediaType.APPLICATION_JSON_VALUE)
                            .content(objectMapper.writeValueAsString(tokenValidationRequest)))
                    .andExpect(status().isOk())
                    .andReturn();

            String json = result.getResponse().getContentAsString();
            TokenValidationResponse response = objectMapper.readValue(json, TokenValidationResponse.class);

            assertTrue(response.valid());

            ReflectionTestUtils.setField(userAuthService, "jwtUtil", jwtUtil);
        }

        @Test
        @DisplayName("return 200 status and negative validation result")
        void shouldNegativelyValidateAccessToken() throws Exception {
            UserPrincipal userPrincipal = new UserPrincipal(
                    login,
                    password,
                    UserRole.ROLE_USER
            );
            AuthRequest authRequest = new AuthRequest(
                    login,
                    password
            );
            userAuthService.register(authRequest);
            AuthResponse authResponse = userAuthService.login(authRequest);
            TokenValidationRequest tokenValidationRequest = new TokenValidationRequest("Bearer " + authResponse.accessToken());
            ReflectionTestUtils.setField(userAuthService, "jwtUtil", jwtUtilSpy);
            when(jwtUtilSpy.isAccessTokenValid(authResponse.accessToken(), userPrincipal)).thenReturn(false);

            MvcResult result = mockMvc.perform(post("/auth/validateAccessToken")
                            .contentType(MediaType.APPLICATION_JSON_VALUE)
                            .content(objectMapper.writeValueAsString(tokenValidationRequest)))
                    .andExpect(status().isOk())
                    .andReturn();

            String json = result.getResponse().getContentAsString();
            TokenValidationResponse response = objectMapper.readValue(json, TokenValidationResponse.class);

            assertFalse(response.valid());

            ReflectionTestUtils.setField(userAuthService, "jwtUtil", jwtUtil);
        }

        @Test
        @DisplayName("return 400 status because request is invalid")
        void shouldReturnBadRequestStatus() throws Exception {
            TokenValidationRequest tokenValidationRequest = new TokenValidationRequest(null);

            mockMvc.perform(post("/auth/validateAccessToken")
                            .contentType(MediaType.APPLICATION_JSON_VALUE)
                            .content(objectMapper.writeValueAsString(tokenValidationRequest)))
                    .andExpect(status().isBadRequest());
        }
    }

    @Nested
    @DisplayName("Tests for /validateRefreshToken")
    class ValidateRefreshTokenTests {
        final String login = "username";
        final String password = "123456";

        @Test
        @DisplayName("return 200 status and positive validation result")
        void shouldPositivelyValidateRefreshToken() throws Exception {
            AuthRequest authRequest = new AuthRequest(
                    login,
                    password
            );
            userAuthService.register(authRequest);
            AuthResponse authResponse = userAuthService.login(authRequest);
            TokenValidationRequest tokenValidationRequest = new TokenValidationRequest("Bearer " + authResponse.refreshToken());

            MvcResult result = mockMvc.perform(post("/auth/validateRefreshToken")
                            .contentType(MediaType.APPLICATION_JSON_VALUE)
                            .content(objectMapper.writeValueAsString(tokenValidationRequest)))
                    .andExpect(status().isOk())
                    .andReturn();

            String json = result.getResponse().getContentAsString();
            TokenValidationResponse response = objectMapper.readValue(json, TokenValidationResponse.class);

            assertTrue(response.valid());
        }

        @Test
        @DisplayName("return 200 status and negative validation result")
        void shouldNegativelyValidateRefreshToken() throws Exception {
            UserPrincipal userPrincipal = new UserPrincipal(
                    login,
                    password,
                    UserRole.ROLE_USER
            );
            AuthRequest authRequest = new AuthRequest(
                    login,
                    password
            );
            userAuthService.register(authRequest);
            AuthResponse authResponse = userAuthService.login(authRequest);
            TokenValidationRequest tokenValidationRequest = new TokenValidationRequest("Bearer " + authResponse.refreshToken());
            ReflectionTestUtils.setField(userAuthService, "jwtUtil", jwtUtilSpy);
            when(jwtUtilSpy.isRefreshTokenValid(authResponse.refreshToken())).thenReturn(false);

            MvcResult result = mockMvc.perform(post("/auth/validateRefreshToken")
                            .contentType(MediaType.APPLICATION_JSON_VALUE)
                            .content(objectMapper.writeValueAsString(tokenValidationRequest)))
                    .andExpect(status().isOk())
                    .andReturn();

            String json = result.getResponse().getContentAsString();
            TokenValidationResponse response = objectMapper.readValue(json, TokenValidationResponse.class);

            assertFalse(response.valid());

            ReflectionTestUtils.setField(userAuthService, "jwtUtil", jwtUtil);
        }

        @Test
        @DisplayName("return 400 status because request is invalid")
        void shouldReturnBadRequestStatus() throws Exception {
            TokenValidationRequest tokenValidationRequest = new TokenValidationRequest(null);

            mockMvc.perform(post("/auth/validateRefreshToken")
                            .contentType(MediaType.APPLICATION_JSON_VALUE)
                            .content(objectMapper.writeValueAsString(tokenValidationRequest)))
                    .andExpect(status().isBadRequest());
        }
    }
}