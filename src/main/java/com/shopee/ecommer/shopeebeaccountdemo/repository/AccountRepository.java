package com.shopee.ecommer.shopeebeaccountdemo.repository;

import com.shopee.ecommer.shopeebeaccountdemo.entity.Account;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface AccountRepository extends JpaRepository<Account, UUID> {
    Account findByUsername(String userName);
}
