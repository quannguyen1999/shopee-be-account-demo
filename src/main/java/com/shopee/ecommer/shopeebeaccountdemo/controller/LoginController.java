package com.shopee.ecommer.shopeebeaccountdemo.controller;

import com.shopee.ecommer.shopeebeaccountdemo.constant.PathApi;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

    @GetMapping(PathApi.LOGIN_PATH)
    public String login(){
        return "login";
    }
}
