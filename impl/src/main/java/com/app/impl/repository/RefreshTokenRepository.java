package com.app.impl.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.app.impl.entity.User;
import com.app.impl.entity.RefreshToken;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByUser(User user);
}