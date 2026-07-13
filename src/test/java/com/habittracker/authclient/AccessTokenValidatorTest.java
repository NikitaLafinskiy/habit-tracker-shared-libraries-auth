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

    private final AccessTokenValidator validator = new AccessTokenValidator(SECRET);

    private String tokenFor(String email, String firstName, String lastName,
                             List<String> authorities, Date expiration) {
        SecretKey key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
        return Jwts.builder()
                .issuedAt(new Date())
                .expiration(expiration)
                .subject(email)
                .claim("email", email)
                .claim("firstName", firstName)
                .claim("lastName", lastName)
                .claim("authorities", authorities)
                .signWith(key)
                .compact();
    }

    @Test
    @DisplayName("""
            Given a token signed with the configured secret and a future expiry
            When validateToken() runs
            Then it returns true
            """)
    void validateToken_unexpiredToken_returnsTrue() {
        String token = tokenFor("user@gmail.com", "First", "Last",
                List.of("ROLE_CUSTOMER"), new Date(System.currentTimeMillis() + 60_000));

        assertTrue(validator.validateToken(token));
    }

    @Test
    @DisplayName("""
            Given a token whose expiration has already passed
            When validateToken() runs
            Then it throws (jjwt rejects expired tokens during parsing itself,
            before the explicit expiration check ever runs) - the caller
            (JwtAuthenticationFilter) treats this the same as a false return
            """)
    void validateToken_expiredToken_throws() {
        String token = tokenFor("user@gmail.com", "First", "Last",
                List.of("ROLE_CUSTOMER"), new Date(System.currentTimeMillis() - 60_000));

        assertThrows(ExpiredJwtException.class, () -> validator.validateToken(token));
    }

    @Test
    @DisplayName("""
            Given a token signed with a different secret
            When validateToken() runs
            Then it throws rather than silently returning false
            """)
    void validateToken_wrongSignature_throws() {
        String otherSecret = "a-completely-different-secret-value-also-256-bits-plus";
        SecretKey wrongKey = Keys.hmacShaKeyFor(otherSecret.getBytes(StandardCharsets.UTF_8));
        String token = Jwts.builder()
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .claim("email", "user@gmail.com")
                .signWith(wrongKey)
                .compact();

        assertThrows(JwtException.class, () -> validator.validateToken(token));
    }

    @Test
    @DisplayName("""
            Given a valid token
            When getAuthentication() runs
            Then it returns an Authentication whose principal and authorities
            are built from the token's claims
            """)
    void getAuthentication_validToken_returnsAuthenticationFromClaims() {
        String token = tokenFor("user@gmail.com", "First", "Last",
                List.of("ROLE_ADMIN", "ROLE_CUSTOMER"),
                new Date(System.currentTimeMillis() + 60_000));

        Authentication authentication = validator.getAuthentication(token);

        JwtPrincipal principal = (JwtPrincipal) authentication.getPrincipal();
        assertThat(principal.getEmail()).isEqualTo("user@gmail.com");
        assertThat(principal.getFirstName()).isEqualTo("First");
        assertThat(principal.getLastName()).isEqualTo("Last");

        assertThat(authentication.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("ROLE_ADMIN", "ROLE_CUSTOMER");
    }
}
