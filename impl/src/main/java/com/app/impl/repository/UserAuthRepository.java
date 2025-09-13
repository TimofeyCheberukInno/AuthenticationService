package com.app.impl.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.app.impl.entity.User;

public interface UserAuthRepository extends JpaRepository<User, Long> {
    Optional<User> findByLogin(String login);
}