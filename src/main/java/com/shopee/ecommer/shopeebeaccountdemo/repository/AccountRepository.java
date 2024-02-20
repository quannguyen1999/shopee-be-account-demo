package com.shopee.ecommer.shopeebeaccountdemo.repository;

import com.shopee.ecommer.shopeebeaccountdemo.entity.Account;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Repository
public interface AccountRepository extends JpaRepository<Account, UUID> {
    Account findByUsername(String userName);

    @Modifying
    @Transactional
    @Query("UPDATE Account a SET a.mfaSecret = :mfaSecret WHERE a.username = :userName")
    void updateMfaSecretByUsername(String mfaSecret, String userName);
}
