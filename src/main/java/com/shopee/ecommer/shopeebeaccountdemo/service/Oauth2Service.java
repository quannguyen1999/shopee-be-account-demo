package com.shopee.ecommer.shopeebeaccountdemo.service;

import dev.samstevens.totp.exceptions.QrGenerationException;
import org.springframework.security.core.context.SecurityContext;

public interface Oauth2Service {

    String registerNewOtpAndGetQrCode(SecurityContext context) throws QrGenerationException;

    Boolean verifyRegisterOtp(SecurityContext context, String code) throws QrGenerationException;
}
