package com.shopee.ecommer.shopeebeaccountdemo.controller;

import com.shopee.ecommer.shopeebeaccountdemo.constant.PathApi;
import com.shopee.ecommer.shopeebeaccountdemo.entity.Account;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping(value = PathApi.ACCOUNT_PATH)
public class AccountController {

    @GetMapping(PathApi.CREATE)
    public ResponseEntity<Account> login(){
        return ResponseEntity.status(HttpStatus.OK)
                .body(Account.builder().id(UUID.randomUUID()).build());
    }

    @GetMapping(PathApi.LIST)
    public ResponseEntity<List<Account>> listAccount(){
        return ResponseEntity.status(HttpStatus.OK).body(List.of(Account.builder().build()));
    }

}
