package com.shopee.ecommer.shopeebeaccountdemo.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@NoArgsConstructor
@AllArgsConstructor
@Data
public class CommonBaseEntities {

    private Date created;

    private Date updated;

    private String userCreated;

    private String userUpdated;

}
