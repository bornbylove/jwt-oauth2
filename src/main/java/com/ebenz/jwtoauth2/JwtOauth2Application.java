package com.ebenz.jwtoauth2;

import com.ebenz.jwtoauth2.config.RSAKeyRecord;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@EnableConfigurationProperties(RSAKeyRecord.class)
@SpringBootApplication
public class JwtOauth2Application {

	public static void main(String[] args) {
		SpringApplication.run(JwtOauth2Application.class, args);
	}

}
