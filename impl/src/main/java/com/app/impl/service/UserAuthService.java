package com.app.impl.service;

import com.app.impl.model.UserPrincipal;
import com.app.impl.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserAuthService implements UserDetailsService {
    private UserRepository userRepository;

    @Autowired
    public void UserAuthService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Transactional(readOnly = true)
    @Override
    public UserPrincipal loadUserByUsername(String login) throws UsernameNotFoundException {
        return userRepository.findByLogin(login)
                .map(user -> new UserPrincipal(
                        user.getLogin(),
                        user.getPasswordHash(),
                        user.getRoles()
                ))
                .orElseThrow(() -> new UsernameNotFoundException(String.format("User with login %s was not found", login)));
    }
}
