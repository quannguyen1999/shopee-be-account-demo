package com.shopee.ecommer.shopeebeaccountdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Profile;

@SpringBootApplication
public class ShopeeBeAccountDemoApplication {
	public static void main(String[] args) {
		SpringApplication.run(ShopeeBeAccountDemoApplication.class, args);
	}

}
