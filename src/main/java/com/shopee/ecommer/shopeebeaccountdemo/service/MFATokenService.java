package com.shopee.ecommer.shopeebeaccountdemo.service;

import dev.samstevens.totp.exceptions.QrGenerationException;

public interface MFATokenService {
    String generateSecretKey();

    String getQRCode(final String secret, String username) throws QrGenerationException;

    boolean verifyTotp(final String code, final String secret);
}
