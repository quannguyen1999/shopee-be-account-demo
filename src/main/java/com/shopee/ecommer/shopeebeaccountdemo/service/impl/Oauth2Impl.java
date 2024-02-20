package com.shopee.ecommer.shopeebeaccountdemo.service.impl;

import com.shopee.ecommer.shopeebeaccountdemo.entity.CustomUserDetails;
import com.shopee.ecommer.shopeebeaccountdemo.repository.AccountRepository;
import com.shopee.ecommer.shopeebeaccountdemo.service.MFATokenService;
import com.shopee.ecommer.shopeebeaccountdemo.service.Oauth2Service;
import dev.samstevens.totp.exceptions.QrGenerationException;
import lombok.AllArgsConstructor;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.stereotype.Service;

@AllArgsConstructor
@Service
public class Oauth2Impl implements Oauth2Service {

    private final MFATokenService mfaTokenService;

    private final AccountRepository accountRepository;

    @Override
    public String registerNewOtpAndGetQrCode(SecurityContext context) throws QrGenerationException {
        String secretKey = mfaTokenService.generateSecretKey();
        accountRepository.updateMfaSecretByUsername(secretKey, getAccount(context).getUsername());
        return mfaTokenService.getQRCode(secretKey);
    }

    @Override
    public Boolean verifyRegisterOtp(SecurityContext context, String code) {
        return mfaTokenService.verifyTotp(code, accountRepository.findByUsername(getAccount(context).getUsername()).getMfaSecret());
    }

    private CustomUserDetails getAccount(SecurityContext context) {
        return (CustomUserDetails) context.getAuthentication().getPrincipal();
    }
}
