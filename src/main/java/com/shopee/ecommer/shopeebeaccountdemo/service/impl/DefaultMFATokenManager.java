package com.shopee.ecommer.shopeebeaccountdemo.service.impl;


import com.shopee.ecommer.shopeebeaccountdemo.service.MFATokenService;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.util.Utils;
import jakarta.annotation.Resource;
import org.springframework.stereotype.Service;


@Service
public class DefaultMFATokenManager implements MFATokenService {
    @Resource
    private SecretGenerator secretGenerator;

    @Resource
    private QrGenerator qrGenerator;

    @Resource
    private CodeVerifier codeVerifier;


    @Override
    public String generateSecretKey() {
        return secretGenerator.generate();
    }

    @Override
    public String getQRCode(String secret, String username) throws QrGenerationException {
        QrData data = new QrData.Builder().label(username)
                .secret(secret)
                .issuer("Ecommerce")
                .algorithm(HashingAlgorithm.SHA256)
                .digits(6)
                .period(30)
                .build();
        return Utils.getDataUriForImage(
                qrGenerator.generate(data),
                qrGenerator.getImageMimeType()
        );
    }

    @Override
    public boolean verifyTotp(String code, String secret) {
        return codeVerifier.isValidCode(secret, code);
    }
}
