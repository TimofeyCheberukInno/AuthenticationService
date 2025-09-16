package com.app.impl.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import com.app.impl.entity.User;
import com.app.impl.entity.RefreshToken;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByUser(User user);

    Optional<RefreshToken> findByTokenHash(String tokenHash);

    @Transactional
    @Modifying
    @Query("UPDATE RefreshToken r " +
            "SET r.tokenHash = :#{#refreshToken.tokenHash} " +
            "WHERE r.user = :#{#refreshToken.user}")
    int updateRefreshToken(@Param("refreshToken") RefreshToken refreshToken);
}