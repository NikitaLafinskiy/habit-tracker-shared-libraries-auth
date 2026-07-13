package com.habittracker.authclient;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
public class AuthClientAutoConfiguration {
    @Bean
    public AccessTokenValidator accessTokenValidator(
            @Value("${jwt.access-secret}") String accessSecret) {
        return new AccessTokenValidator(accessSecret);
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(
            AccessTokenValidator accessTokenValidator) {
        return new JwtAuthenticationFilter(accessTokenValidator);
    }
}
