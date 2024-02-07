package com.shopee.ecommer.shopeebeaccountdemo.utils;

import com.j256.twofactorauth.TimeBasedOneTimePasswordUtil;

import java.security.GeneralSecurityException;

public class AuthenticationUtil {
    public static boolean check(String key, String code) {
        try {
            return TimeBasedOneTimePasswordUtil.validateCurrentNumber(key, Integer.parseInt(code), 10000);
        } catch (IllegalArgumentException ex) {
            return false;
        } catch (GeneralSecurityException ex) {
            throw new IllegalArgumentException(ex);
        }
    }

    public static String generateSecret() {
        return TimeBasedOneTimePasswordUtil.generateBase32Secret();
    }

    public static String getCode(String base32Secret) throws GeneralSecurityException {
        return TimeBasedOneTimePasswordUtil.generateCurrentNumberString(base32Secret);
    }

    public static String generateQrImageUrl(String keyId, String base32Secret) {
        return TimeBasedOneTimePasswordUtil.qrImageUrl(keyId, base32Secret);
    }

}
