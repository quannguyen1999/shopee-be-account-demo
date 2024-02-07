package com.shopee.ecommer.shopeebeaccountdemo.service;

import com.shopee.ecommer.shopeebeaccountdemo.entity.Account;
import com.shopee.ecommer.shopeebeaccountdemo.entity.CustomUserDetails;
import com.shopee.ecommer.shopeebeaccountdemo.repository.AccountRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.encrypt.BytesEncryptor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.ObjectUtils;

import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.HashSet;

@RequiredArgsConstructor
@Service
public class UserDetailConfigService implements UserDetailsService {

    private final AccountRepository accountRepository;

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    private final BytesEncryptor bytesEncryptor;

    @Transactional
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = accountRepository.findByUsername(username);
        if (ObjectUtils.isEmpty(account)) {
            throw new UsernameNotFoundException("Access Denied " + username);
        }
        Collection<GrantedAuthority> authorities = new HashSet<>();
        account.getRoleAccountList().forEach(auth -> authorities.add(new SimpleGrantedAuthority(auth.getCode())));
//        return new User(account.getUsername(), account.getPassword(), account.getIsActive(),
//                true, true, true, authorities);
        return new CustomUserDetails(
                new Account(account.getId(), account.getUsername(), account.getPassword(), account.getBirthday(),
                        account.getGender(), account.getEmail(), account.getAvatar(), account.getIsActive(),
                        account.getSecurityQuestion(), account.getSecurityAnswer(), account.getMfaSecret(),
                        account.getMfaKeyId(), account.getMfaEnabled(), account.getMfaRegistered(), account.getSecurityQuestionEnabled(),
                        account.getRoleAccountList()));
    }

    public void saveUserInfoMfaRegistered(String secret, String username) {
        String encryptedSecret = new String(Hex.encode(this.bytesEncryptor.encrypt(secret.getBytes(StandardCharsets.UTF_8))));
        Account account = accountRepository.findByUsername(username);
        account.setMfaSecret(encryptedSecret);
        account.setMfaRegistered(true);
        accountRepository.save(account);
    }

}
