package com.habittracker.authclient;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;
import javax.crypto.SecretKey;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class AccessTokenValidator {
    private static final String EMAIL_CLAIM = "email";
    private static final String FIRST_NAME_CLAIM = "firstName";
    private static final String LAST_NAME_CLAIM = "lastName";
    private static final String AUTHORITIES_CLAIM = "authorities";

    private final SecretKey accessSecretKey;

    public AccessTokenValidator(String accessSecret) {
        this.accessSecretKey = Keys.hmacShaKeyFor(accessSecret.getBytes(StandardCharsets.UTF_8));
    }

    public boolean validateToken(String token) {
        Claims claims = parseClaims(token);
        return claims.getExpiration().after(new Date());
    }

    public Authentication getAuthentication(String token) {
        Claims claims = parseClaims(token);

        JwtPrincipal principal =
                new JwtPrincipal(
                        claims.get(EMAIL_CLAIM, String.class),
                        claims.get(FIRST_NAME_CLAIM, String.class),
                        claims.get(LAST_NAME_CLAIM, String.class));

        List<String> authorityNames = claims.get(AUTHORITIES_CLAIM, List.class);
        List<GrantedAuthority> authorities =
                authorityNames.stream()
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        return new UsernamePasswordAuthenticationToken(principal, null, authorities);
    }

    private Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(accessSecretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
