package com.shopee.ecommer.shopeebeaccountdemo.controller;

import com.shopee.ecommer.shopeebeaccountdemo.config.SecurityConfig;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

    @GetMapping(SecurityConfig.DEFAULT_URL_LOGIN_PATH)
    public String login(){
        return "login";
    }
}
