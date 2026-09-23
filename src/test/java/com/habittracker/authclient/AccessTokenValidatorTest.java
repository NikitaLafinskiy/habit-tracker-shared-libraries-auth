package com.habittracker.authclient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

class AccessTokenValidatorTest {
    private static final String SECRET = "test-access-secret-at-least-256-bits-long-for-hmac-sha";
    private static final String USER_ID = "3f0e8c1a-6b2d-4c5e-9f7a-1b2c3d4e5f60";

    private final AccessTokenValidator validator = new AccessTokenValidator(SECRET);

    private String tokenFor(
            String email,
            String firstName,
            String lastName,
            List<String> authorities,
            Date expiration) {
        return tokenFor(USER_ID, email, firstName, lastName, authorities, expiration);
    }

    private String tokenFor(
            String subject,
            String email,
            String firstName,
            String lastName,
            List<String> authorities,
            Date expiration) {
        SecretKey key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
        return Jwts.builder()
                .issuedAt(new Date())
                .expiration(expiration)
                .subject(subject)
                .claim("email", email)
                .claim("firstName", firstName)
                .claim("lastName", lastName)
                .claim("authorities", authorities)
                .signWith(key)
                .compact();
    }

    @Test
    @DisplayName(
            """
            Given a token signed with the configured secret and a future expiry
            When validateToken() runs
            Then it returns true
            """)
    void validateToken_unexpiredToken_returnsTrue() {
        String token =
                tokenFor(
                        "user@gmail.com",
                        "First",
                        "Last",
                        List.of("ROLE_CUSTOMER"),
                        new Date(System.currentTimeMillis() + 60_000));

        assertTrue(validator.validateToken(token));
    }

    @Test
    @DisplayName(
            """
            Given a token whose expiration has already passed
            When validateToken() runs
            Then it throws (jjwt rejects expired tokens during parsing itself,
            before the explicit expiration check ever runs) - the caller
            (JwtAuthenticationFilter) treats this the same as a false return
            """)
    void validateToken_expiredToken_throws() {
        String token =
                tokenFor(
                        "user@gmail.com",
                        "First",
                        "Last",
                        List.of("ROLE_CUSTOMER"),
                        new Date(System.currentTimeMillis() - 60_000));

        assertThrows(ExpiredJwtException.class, () -> validator.validateToken(token));
    }

    @Test
    @DisplayName(
            """
            Given a token signed with a different secret
            When validateToken() runs
            Then it throws rather than silently returning false
            """)
    void validateToken_wrongSignature_throws() {
        String otherSecret = "a-completely-different-secret-value-also-256-bits-plus";
        SecretKey wrongKey = Keys.hmacShaKeyFor(otherSecret.getBytes(StandardCharsets.UTF_8));
        String token =
                Jwts.builder()
                        .issuedAt(new Date())
                        .expiration(new Date(System.currentTimeMillis() + 60_000))
                        .claim("email", "user@gmail.com")
                        .signWith(wrongKey)
                        .compact();

        assertThrows(JwtException.class, () -> validator.validateToken(token));
    }

    @Test
    @DisplayName(
            """
            Given a valid token
            When getAuthentication() runs
            Then it returns an Authentication whose principal and authorities
            are built from the token's claims
            """)
    void getAuthentication_validToken_returnsAuthenticationFromClaims() {
        String token =
                tokenFor(
                        "user@gmail.com",
                        "First",
                        "Last",
                        List.of("ROLE_ADMIN", "ROLE_CUSTOMER"),
                        new Date(System.currentTimeMillis() + 60_000));

        Authentication authentication = validator.getAuthentication(token);

        JwtPrincipal principal = (JwtPrincipal) authentication.getPrincipal();
        assertThat(principal.getUserId()).isEqualTo(USER_ID);
        assertThat(principal.getEmail()).isEqualTo("user@gmail.com");
        assertThat(principal.getFirstName()).isEqualTo("First");
        assertThat(principal.getLastName()).isEqualTo("Last");

        assertThat(authentication.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("ROLE_ADMIN", "ROLE_CUSTOMER");
    }

    @Test
    @DisplayName(
            """
            Given an unexpired token minted before the user-id migration, whose
            subject is an email
            When validateToken() runs
            Then it returns false, so the client refreshes into a UUID token
            """)
    void validateToken_emailSubject_returnsFalse() {
        String token =
                tokenFor(
                        "user@gmail.com",
                        "user@gmail.com",
                        "First",
                        "Last",
                        List.of("ROLE_CUSTOMER"),
                        new Date(System.currentTimeMillis() + 60_000));

        assertThat(validator.validateToken(token)).isFalse();
    }

    @Test
    @DisplayName(
            """
            Given subjects that are not canonical UUIDs
            When isUserId() runs
            Then only the canonical lowercase UUID passes
            """)
    void isUserId_onlyCanonicalUuids() {
        assertThat(AccessTokenValidator.isUserId(USER_ID)).isTrue();
        assertThat(AccessTokenValidator.isUserId("user@gmail.com")).isFalse();
        assertThat(AccessTokenValidator.isUserId(USER_ID.toUpperCase())).isFalse();
        assertThat(AccessTokenValidator.isUserId(null)).isFalse();
    }
}
