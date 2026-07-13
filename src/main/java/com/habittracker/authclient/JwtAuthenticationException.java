package com.habittracker.authclient;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class JwtAuthenticationException extends RuntimeException {
    private final HttpStatus statusCode;

    public JwtAuthenticationException(String message, HttpStatus statusCode) {
        super(message);
        this.statusCode = statusCode;
    }
}
