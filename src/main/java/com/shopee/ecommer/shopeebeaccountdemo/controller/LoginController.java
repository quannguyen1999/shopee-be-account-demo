package com.shopee.ecommer.shopeebeaccountdemo.controller;

import com.shopee.ecommer.shopeebeaccountdemo.constant.ConstantUtil;
import com.shopee.ecommer.shopeebeaccountdemo.constant.PathApi;
import com.shopee.ecommer.shopeebeaccountdemo.entity.Account;
import com.shopee.ecommer.shopeebeaccountdemo.entity.CustomUserDetails;
import com.shopee.ecommer.shopeebeaccountdemo.service.Oauth2Service;
import com.shopee.ecommer.shopeebeaccountdemo.service.UserDetailConfigService;
import dev.samstevens.totp.exceptions.QrGenerationException;
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

import static com.shopee.ecommer.shopeebeaccountdemo.constant.PathApi.AUTHENTICATOR_PATH;
import static com.shopee.ecommer.shopeebeaccountdemo.constant.PathApi.REGISTRATION_PATH;

@Controller
public class LoginController {
    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();
    private final AuthenticationFailureHandler authenticatorFailureHandler =
            new SimpleUrlAuthenticationFailureHandler("/authenticator?error");

    private final Oauth2Service oauth2Service;
    private final AuthenticationSuccessHandler authenticationSuccessHandler;
    private final UserDetailConfigService userDetailConfigService;

    public LoginController(AuthenticationSuccessHandler authenticationSuccessHandler,
                           UserDetailConfigService userDetailConfigService,
                           Oauth2Service oauth2Service
    ) {
        this.authenticationSuccessHandler = authenticationSuccessHandler;
        this.userDetailConfigService = userDetailConfigService;
        this.oauth2Service = oauth2Service;
    }

    @GetMapping(PathApi.LOGIN_PATH)
    public String login() {
        return "login";
    }

    @GetMapping(REGISTRATION_PATH)
    public String registration(
            Model model,
            HttpServletRequest request,
            @CurrentSecurityContext SecurityContext context) throws QrGenerationException {
        model.addAttribute("qrImage", oauth2Service.registerNewOtpAndGetQrCode(context));
        return "registration";
    }

    @PostMapping(REGISTRATION_PATH)
    public void validateRegistration(@RequestParam("code") String code,
                                     HttpServletRequest request,
                                     HttpServletResponse response,
                                     @CurrentSecurityContext SecurityContext context) throws ServletException, IOException, QrGenerationException {
        if (oauth2Service.verifyRegisterOtp(context, code)) {
            userDetailConfigService.saveUserInfoMfaRegistered(getUser(context).getUsername());
            request.getSession().setAttribute(ConstantUtil.ATTRIBUTE_MFA, Boolean.TRUE);
            this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, getAuthentication(request, response));
            return;
        }
        this.authenticatorFailureHandler.onAuthenticationFailure(request, response, new BadCredentialsException("bad credentials"));
    }

    @GetMapping(AUTHENTICATOR_PATH)
    public String authenticator(
            @CurrentSecurityContext SecurityContext context) {
        if (!getUser(context).getMfaRegistered()) {
            return "redirect:registration";
        }
        return "authenticator";
    }

    @PostMapping(AUTHENTICATOR_PATH)
    public void validateCode(
            @RequestParam("code") String code,
            HttpServletRequest request,
            HttpServletResponse response,
            @CurrentSecurityContext SecurityContext context) throws ServletException, IOException, QrGenerationException {
        if (oauth2Service.verifyRegisterOtp(context, code)) {
            request.getSession().setAttribute(ConstantUtil.ATTRIBUTE_MFA, Boolean.TRUE);
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
