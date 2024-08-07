package com.shopee.ecommer.shopeebeaccountdemo.config.mfa;

import com.shopee.ecommer.shopeebeaccountdemo.constant.ConstantUtil;
import com.shopee.ecommer.shopeebeaccountdemo.entity.CustomUserDetails;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

import java.io.IOException;


public class MfaHandlerSuccess implements AuthenticationSuccessHandler {
    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();
    private final AuthenticationSuccessHandler mfaNotEnabled = new SavedRequestAwareAuthenticationSuccessHandler();
    private final AuthenticationSuccessHandler authenticationSuccessHandler;
    private final String authority;

    public MfaHandlerSuccess(String successUrl, String authority) {
        SimpleUrlAuthenticationSuccessHandler authenticationSuccessHandler =
                new SimpleUrlAuthenticationSuccessHandler(successUrl);
        authenticationSuccessHandler.setAlwaysUseDefaultTargetUrl(true);
        this.authenticationSuccessHandler = authenticationSuccessHandler;
        this.authority = authority;
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
        if (authentication instanceof UsernamePasswordAuthenticationToken) {
            CustomUserDetails userdetails = (CustomUserDetails) authentication.getPrincipal();
            if (!userdetails.getUser().getMfaEnabled()) {
                //if mfa not enable, we will set attribute mfa true to allow continue filter
                request.getSession().setAttribute(ConstantUtil.ATTRIBUTE_MFA, Boolean.TRUE);
                mfaNotEnabled.onAuthenticationSuccess(request, response, authentication);
                return;
            }
        }
        saveAuthentication(request, response, new MfaAuthentication(authentication, authority));
        this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, authentication);
    }

    private void saveAuthentication(
            HttpServletRequest request,
            HttpServletResponse response,
            MfaAuthentication authentication) {
        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(authentication);
        SecurityContextHolder.setContext(securityContext);
        securityContextRepository.saveContext(securityContext, request, response);
    }

}
