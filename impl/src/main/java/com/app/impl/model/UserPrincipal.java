package com.app.impl.model;

import java.util.Collection;
import java.util.Collections;
import java.util.Objects;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.app.impl.enums.UserRole;

public class UserPrincipal implements UserDetails {
    private final String login;
    private final String password;
    private final Collection<? extends GrantedAuthority> authorities;

    public UserPrincipal(
            String login,
            String password,
            UserRole authority
    ) {
        this.login = login;
        this.password = password;
        this.authorities = Collections.singleton(new SimpleGrantedAuthority(authority.getName()));
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.login;
    }

    @Override
    public boolean isAccountNonExpired() {
        return UserDetails.super.isAccountNonExpired();
    }

    @Override
    public boolean isAccountNonLocked() {
        return UserDetails.super.isAccountNonLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return UserDetails.super.isCredentialsNonExpired();
    }

    @Override
    public boolean isEnabled() {
        return UserDetails.super.isEnabled();
    }

    @Override
    public boolean equals(Object o) {
        if(this == o)
            return true;
        if(o == null || this.getClass() != o.getClass())
            return false;
        UserPrincipal principal = (UserPrincipal)o;
        return this.login.equals(principal.login);
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.login);
    }

    @Override
    public String toString() {
        return "UserPrincipal{" +
                "login='" + login + '\'' +
                ", authorities=" + authorities +
                '}';
    }
}
