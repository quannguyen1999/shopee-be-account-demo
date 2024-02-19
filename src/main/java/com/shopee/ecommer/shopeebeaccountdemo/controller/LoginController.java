package com.shopee.ecommer.shopeebeaccountdemo.controller;

import com.shopee.ecommer.shopeebeaccountdemo.constant.ConstantUtil;
import com.shopee.ecommer.shopeebeaccountdemo.constant.PathApi;
import com.shopee.ecommer.shopeebeaccountdemo.entity.Account;
import com.shopee.ecommer.shopeebeaccountdemo.entity.CustomUserDetails;
import com.shopee.ecommer.shopeebeaccountdemo.service.MFATokenService;
import com.shopee.ecommer.shopeebeaccountdemo.service.UserDetailConfigService;
import com.shopee.ecommer.shopeebeaccountdemo.utils.AuthenticationUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;
import java.security.GeneralSecurityException;

@Controller
public class LoginController {
    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();
    private final AuthenticationFailureHandler authenticatorFailureHandler =
            new SimpleUrlAuthenticationFailureHandler("/authenticator?error");

    private final MFATokenService mfaTokenService;

    private final AuthenticationSuccessHandler authenticationSuccessHandler;
    private final UserDetailConfigService userDetailConfigService;
    private String generatedCode = "";
    private String base32Secret = "";
    private String keyId = "";

    public LoginController(AuthenticationSuccessHandler authenticationSuccessHandler,
                           UserDetailConfigService userDetailConfigService,
                           MFATokenService mfaTokenService
    ) {
        this.authenticationSuccessHandler = authenticationSuccessHandler;
        this.userDetailConfigService = userDetailConfigService;
        this.mfaTokenService = mfaTokenService;
    }

    @GetMapping(PathApi.LOGIN_PATH)
    public String login() {
        return "login";
    }

    @GetMapping("/registration")
    public String registration(
            Model model,
            HttpServletRequest request,
            @CurrentSecurityContext SecurityContext context) {
        base32Secret = AuthenticationUtil.generateSecret();
        keyId = getUser(context).getMfaKeyId();
        try {
            generatedCode = AuthenticationUtil.getCode(base32Secret);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        model.addAttribute("qrImage", AuthenticationUtil.generateQrImageUrl(keyId, base32Secret));
        return "registration";
    }

    @PostMapping("/registration")
    public void validateRegistration(@RequestParam("code") String code,
                                     HttpServletRequest request,
                                     HttpServletResponse response,
                                     @CurrentSecurityContext SecurityContext context) throws ServletException, IOException {
        if (code.equalsIgnoreCase(generatedCode)) {
            userDetailConfigService.saveUserInfoMfaRegistered(base32Secret, getUser(context).getUsername());
            request.getSession().setAttribute(ConstantUtil.ATTRIBUTE_MFA, "true");
            this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, getAuthentication(request, response));
            return;
        }
        this.authenticatorFailureHandler.onAuthenticationFailure(request, response, new BadCredentialsException("bad credentials"));
    }

    @GetMapping("/authenticator")
    public String authenticator(
            @CurrentSecurityContext SecurityContext context) {
        if (!getUser(context).getMfaRegistered()) {
            return "redirect:registration";
        }
        return "authenticator";
    }

    @PostMapping("/authenticator")
    public void validateCode(
            @RequestParam("code") String code,
            HttpServletRequest request,
            HttpServletResponse response,
            @CurrentSecurityContext SecurityContext context) throws ServletException, IOException {
        if (code.equals("1000")) {
            request.getSession().setAttribute(ConstantUtil.ATTRIBUTE_MFA, "true");
            this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, getAuthentication(request, response));
            return;
        }
        this.authenticatorFailureHandler.onAuthenticationFailure(request, response, new BadCredentialsException("bad credentials"));
    }

    private Authentication getAuthentication(
            HttpServletRequest request,
            HttpServletResponse response) {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        securityContext.setAuthentication(securityContext.getAuthentication());
        SecurityContextHolder.setContext(securityContext);
        securityContextRepository.saveContext(securityContext, request, response);
        return securityContext.getAuthentication();
    }

    private Account getUser(SecurityContext context) {
        CustomUserDetails userDetails = (CustomUserDetails) context.getAuthentication().getPrincipal();
        return userDetails.getUser();
    }
}
