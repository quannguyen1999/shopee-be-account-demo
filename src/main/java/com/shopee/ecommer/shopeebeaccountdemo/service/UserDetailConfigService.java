package com.shopee.ecommer.shopeebeaccountdemo.service;

import com.shopee.ecommer.shopeebeaccountdemo.entity.Account;
import com.shopee.ecommer.shopeebeaccountdemo.entity.CustomUserDetails;
import com.shopee.ecommer.shopeebeaccountdemo.repository.AccountRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.ObjectUtils;

@RequiredArgsConstructor
@Service
public class UserDetailConfigService implements UserDetailsService {

    private final AccountRepository accountRepository;

    @Transactional
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = accountRepository.findByUsername(username);
        if (ObjectUtils.isEmpty(account)) {
            throw new UsernameNotFoundException("Access Denied " + username);
        }
        return new CustomUserDetails(
                new Account(account.getId(), account.getUsername(), account.getPassword(), account.getBirthday(),
                        account.getGender(), account.getEmail(), account.getAvatar(), account.getIsActive(),
                        account.getSecurityQuestion(), account.getSecurityAnswer(), account.getMfaSecret(),
                        account.getMfaKeyId(), account.getMfaEnabled(), account.getMfaRegistered(), account.getSecurityQuestionEnabled(),
                        account.getRoleAccountList()));
    }

    public void saveUserInfoMfaRegistered(String username) {
        Account account = accountRepository.findByUsername(username);
        account.setMfaRegistered(true);
        accountRepository.save(account);
    }

}
