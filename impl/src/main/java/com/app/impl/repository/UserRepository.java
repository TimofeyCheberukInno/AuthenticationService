package com.app.impl.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.app.impl.entity.User;

public interface UserRepository extends JpaRepository<User, Long> {
}
