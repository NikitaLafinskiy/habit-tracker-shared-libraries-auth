package com.habittracker.authclient;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public class JwtPrincipal {
    private final String email;
    private final String firstName;
    private final String lastName;
}
