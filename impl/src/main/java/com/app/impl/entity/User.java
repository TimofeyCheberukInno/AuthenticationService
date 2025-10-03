package com.app.impl.entity;

import java.util.Objects;

import jakarta.persistence.*;

import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.Builder;

import com.app.impl.enums.UserRole;

@Entity
@Table(name = "users_auth")
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Builder
public class User extends AuditableEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "login", unique = true, nullable = false)
    private String login;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @Enumerated(EnumType.STRING)
    @Column(name = "user_roles", nullable = false)
    private UserRole role;

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || this.getClass() != o.getClass())
            return false;
        User user = (User) o;

        return Objects.equals(this.login, user.login);
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.login);
    }

    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", login='" + login + '\'' +
                ", roles=" + role +
                '}';
    }
}