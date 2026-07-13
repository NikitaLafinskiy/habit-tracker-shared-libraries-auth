package com.habittracker.authclient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

class JwtAuthenticationFilterTest {
    private final AccessTokenValidator accessTokenValidator = mock(AccessTokenValidator.class);
    private final JwtAuthenticationFilter filter =
            new JwtAuthenticationFilter(accessTokenValidator);

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("""
            Given a request with no Authorization header
            When the filter runs
            Then it passes the request through without touching the security context
            """)
    void doFilterInternal_noAuthorizationHeader_passesThroughUnauthenticated() throws Exception {
        // Given
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain filterChain = mock(FilterChain.class);
        when(request.getHeader("Authorization")).thenReturn(null);

        // When
        filter.doFilterInternal(request, response, filterChain);

        // Then
        verify(filterChain).doFilter(request, response);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    @DisplayName("""
            Given a request with a valid Bearer token
            When the filter runs
            Then it sets the Authentication from the validator and continues the chain
            """)
    void doFilterInternal_validToken_setsAuthenticationAndContinues() throws Exception {
        // Given
        HttpServletRequest request = mock(HttpServletRequest.class);
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                new JwtPrincipal("user@gmail.com", "First", "Last"), null, List.of());

        when(request.getHeader("Authorization")).thenReturn("Bearer valid-token");
        when(accessTokenValidator.validateToken("valid-token")).thenReturn(true);
        when(accessTokenValidator.getAuthentication("valid-token")).thenReturn(authentication);

        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain filterChain = mock(FilterChain.class);

        // When
        filter.doFilterInternal(request, response, filterChain);

        // Then
        verify(filterChain).doFilter(request, response);
        Authentication actual = SecurityContextHolder.getContext().getAuthentication();
        assertThat(actual).isEqualTo(authentication);
    }

    @Test
    @DisplayName("""
            Given a request with an expired/invalid Bearer token
            When the filter runs
            Then it throws JwtAuthenticationException and never continues the chain
            """)
    void doFilterInternal_invalidToken_throwsAndNeverContinuesChain() throws Exception {
        // Given
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain filterChain = mock(FilterChain.class);
        when(request.getHeader("Authorization")).thenReturn("Bearer invalid-token");
        when(accessTokenValidator.validateToken("invalid-token")).thenReturn(false);

        // When / Then
        JwtAuthenticationException exception = assertThrows(JwtAuthenticationException.class,
                () -> filter.doFilterInternal(request, response, filterChain));
        assertThat(exception.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    @DisplayName("""
            Given the validator itself throws (e.g. malformed/tampered token)
            When the filter runs
            Then it throws JwtAuthenticationException rather than the raw exception
            """)
    void doFilterInternal_validatorThrows_throwsJwtAuthenticationException() {
        // Given
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain filterChain = mock(FilterChain.class);
        when(request.getHeader("Authorization")).thenReturn("Bearer malformed-token");
        when(accessTokenValidator.validateToken("malformed-token"))
                .thenThrow(new RuntimeException("malformed"));

        // When / Then
        assertThrows(JwtAuthenticationException.class,
                () -> filter.doFilterInternal(request, response, filterChain));
    }
}
