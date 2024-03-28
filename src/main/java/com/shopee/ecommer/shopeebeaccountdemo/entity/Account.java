package com.shopee.ecommer.shopeebeaccountdemo.entity;

import jakarta.persistence.*;
import lombok.*;

import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "Account")
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Builder
public class Account extends CommonBaseEntities {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    private String username;

    private String password;

    private Date birthday;

    private Boolean gender;

    private String email;

    private String avatar;

    private Boolean isActive;

//    private Boolean isAccountNonExpired;
//
//    private Boolean isCredentialsNonExpired;

    private String securityQuestion;

    private String securityAnswer;

    private String mfaSecret;

    private String mfaKeyId;

    private Boolean mfaEnabled;

    private Boolean mfaRegistered;

    private Boolean securityQuestionEnabled;

    @ManyToMany(fetch = FetchType.EAGER,
            cascade = {
                    CascadeType.PERSIST,
                    CascadeType.MERGE
            })
    @JoinTable(name = "accountRoles",
            joinColumns = {@JoinColumn(name = "account_id")},
            inverseJoinColumns = {@JoinColumn(name = "role_id")})
    private Set<RoleAccount> roleAccountList = new HashSet<>();

}
