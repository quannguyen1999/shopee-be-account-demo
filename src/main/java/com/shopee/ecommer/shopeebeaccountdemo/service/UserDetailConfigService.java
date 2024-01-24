package com.shopee.ecommer.shopeebeaccountdemo.service;

import com.shopee.ecommer.shopeebeaccountdemo.entity.Account;
import com.shopee.ecommer.shopeebeaccountdemo.repository.AccountRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.ObjectUtils;

import java.util.Collection;
import java.util.HashSet;

@RequiredArgsConstructor
@Service
public class UserDetailConfigService implements UserDetailsService {

    private final AccountRepository accountRepository;

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Transactional
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = accountRepository.findByUsername(username);
        if (ObjectUtils.isEmpty(account)) {
            throw new UsernameNotFoundException("Access Denied " + username);
        }
        Collection<GrantedAuthority> authorities = new HashSet<>();
        account.getRoleAccountList().forEach(auth -> authorities.add(new SimpleGrantedAuthority(auth.getCode())));
        return new User(account.getUsername(), account.getPassword(), account.getIsActive(),
                true, true, true, authorities);
    }

}
