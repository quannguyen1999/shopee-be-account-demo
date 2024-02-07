package com.shopee.ecommer.shopeebeaccountdemo.entity;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.HashSet;

public class CustomUserDetails implements UserDetails {

    private static final long serialVersionUID = 1L;
    private final Account account;

    public CustomUserDetails(Account account) {
        this.account = account;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> authorities = new HashSet<>();
        account.getRoleAccountList().forEach(auth -> authorities.add(new SimpleGrantedAuthority(auth.getCode())));
        return authorities;
    }

    @Override
    public String getPassword() {
        return account.getPassword();
    }

    @Override
    public String getUsername() {
        return account.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return account.getIsActive();
    }

    public Account getUser() {
        return new Account(account.getId(), account.getUsername(), account.getPassword(), account.getBirthday(),
                account.getGender(), account.getEmail(), account.getAvatar(), account.getIsActive(),
                account.getSecurityQuestion(), account.getSecurityAnswer(), account.getMfaSecret(),
                account.getMfaKeyId(), account.getMfaEnabled(), account.getMfaRegistered(), account.getSecurityQuestionEnabled(),
                account.getRoleAccountList()
        );
    }


}
