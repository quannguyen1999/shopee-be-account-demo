package com.shopee.ecommer.shopeebeaccountdemo.config.mfa;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;

public class MfaAuthentication extends AnonymousAuthenticationToken {

    private static final long serialVersionUID = 1L;
    private final Authentication primaryAuthentication;

    public MfaAuthentication(Authentication authentication, String authority) {
        super("anonymous", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS", authority));
        this.primaryAuthentication = authentication;
    }

    public Authentication getPrimaryAuthentication() {
        return this.primaryAuthentication;
    }

    @Override
    public Object getPrincipal() {
        return this.primaryAuthentication.getPrincipal();
    }


}
