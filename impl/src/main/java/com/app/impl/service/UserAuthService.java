package com.app.impl.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.app.impl.enums.UserRole;
import com.app.impl.dto.auth.AuthResponse;
import com.app.impl.dto.auth.AuthRequest;
import com.app.impl.entity.User;
import com.app.impl.exception.UserAlreadyExistsException;
import com.app.impl.util.JwtUtil;
import com.app.impl.model.UserPrincipal;
import com.app.impl.repository.UserAuthRepository;
import com.app.impl.exception.UserPrincipalNotFoundException;

@Service
public class UserAuthService implements UserDetailsService {
    private final UserAuthRepository userAuthRepository;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public UserAuthService(
            UserAuthRepository userAuthRepository,
            JwtUtil jwtUtil,
            PasswordEncoder passwordEncoder
    ) {
        this.userAuthRepository = userAuthRepository;
        this.jwtUtil = jwtUtil;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional(readOnly = true)
    @Override
    public UserPrincipal loadUserByUsername(String login) {
        return userAuthRepository.findByLogin(login)
                .map(user -> new UserPrincipal(
                        user.getLogin(),
                        user.getPasswordHash(),
                        user.getRoles()
                ))
                .orElseThrow(() -> new UserPrincipalNotFoundException(String.format("User with login %s was not found", login)));
    }

    @Transactional
    public void register(AuthRequest request) {
        final String login = request.login();

        if(userAuthRepository.findByLogin(login).isPresent()) {
            throw new UserAlreadyExistsException(login);
        }

        User user = User.builder()
                .login(login)
                .passwordHash(passwordEncoder.encode(request.password()))
                .roles(new ArrayList<>(List.of(UserRole.ROLE_USER)))
                .build();

        userAuthRepository.save(user);
    }

    @Transactional(readOnly = true)
    public AuthResponse login(AuthRequest request) {
        User user = userAuthRepository.findByLogin(request.login())
                .orElseThrow(() -> new UserPrincipalNotFoundException("User with login " + request.login() + " was not found"));

        if(!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            throw new BadCredentialsException("Incorrect password of user with login " + request.login());
        }

        UserPrincipal userPrincipal = loadUserByUsername(request.login());
        String accessToken = jwtUtil.generateAccessToken(userPrincipal);
        String refreshToken = jwtUtil.generateRefreshToken(userPrincipal);
        return new AuthResponse(accessToken, refreshToken);
    }
}