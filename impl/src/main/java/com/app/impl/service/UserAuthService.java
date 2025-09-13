package com.app.impl.service;

import com.app.impl.exception.UserPrincipalNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.app.impl.util.JwtUtil;
import com.app.impl.model.UserPrincipal;
import com.app.impl.repository.UserAuthRepository;

@Service
public class UserAuthService implements UserDetailsService {
    private UserAuthRepository userAuthRepository;
    private JwtUtil jwtUtil;

    @Autowired
    public void UserAuthService(
            UserAuthRepository userAuthRepository,
            JwtUtil jwtUtil
    ) {
        this.userAuthRepository = userAuthRepository;
        this.jwtUtil = jwtUtil;
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
}
