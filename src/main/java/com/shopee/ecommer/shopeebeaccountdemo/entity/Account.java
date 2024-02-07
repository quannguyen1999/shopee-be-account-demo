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

    @ManyToMany(fetch = FetchType.LAZY,
            cascade = {
                    CascadeType.PERSIST,
                    CascadeType.MERGE
            })
    @JoinTable(name = "accountRoles",
            joinColumns = {@JoinColumn(name = "account_id")},
            inverseJoinColumns = {@JoinColumn(name = "role_id")})
    private Set<RoleAccount> roleAccountList = new HashSet<>();

//    public Account(Date created, Date updated, String userCreated, String userUpdated,
//                   UUID id, String username, String password, Date birthday, Boolean gender, String email,
//                   String avatar, Boolean isActive, String securityQuestion, String securityAnswer, String mfaSecret,
//                   String mfaKeyId, Boolean mfaEnabled, Boolean mfaRegistered, Boolean securityQuestionEnabled) {
//        super(created, updated, userCreated, userUpdated);
//        this.id = id;
//        this.username = username;
//        this.password = password;
//        this.birthday = birthday;
//        this.gender = gender;
//        this.email = email;
//        this.avatar = avatar;
//        this.isActive = isActive;
//        this.securityQuestion = securityQuestion;
//        this.securityAnswer = securityAnswer;
//        this.mfaSecret = mfaSecret;
//        this.mfaKeyId = mfaKeyId;
//        this.mfaEnabled = mfaEnabled;
//        this.mfaRegistered = mfaRegistered;
//        this.securityQuestionEnabled = securityQuestionEnabled;
//    }
//
//    public Account(UUID id, String username, String password, Date birthday, Boolean gender, String email, String avatar, Boolean isActive, String securityQuestion, String securityAnswer, String mfaSecret, String mfaKeyId, Boolean mfaEnabled, Boolean mfaRegistered, Boolean securityQuestionEnabled) {
//        this.id = id;
//        this.username = username;
//        this.password = password;
//        this.birthday = birthday;
//        this.gender = gender;
//        this.email = email;
//        this.avatar = avatar;
//        this.isActive = isActive;
//        this.securityQuestion = securityQuestion;
//        this.securityAnswer = securityAnswer;
//        this.mfaSecret = mfaSecret;
//        this.mfaKeyId = mfaKeyId;
//        this.mfaEnabled = mfaEnabled;
//        this.mfaRegistered = mfaRegistered;
//        this.securityQuestionEnabled = securityQuestionEnabled;
//    }
}
