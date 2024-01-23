package com.shopee.ecommer.shopeebeaccountdemo.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;

import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "RoleAccount")
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Builder
public class RoleAccount extends CommonBaseEntities {
    @Id
    private String code;

    private String name;

    @ManyToMany(fetch = FetchType.LAZY,
            cascade = {
                    CascadeType.PERSIST,
                    CascadeType.MERGE
            },
            mappedBy = "roleAccountList")
    @JsonIgnore
    private Set<Account> account = new HashSet<>();
}
