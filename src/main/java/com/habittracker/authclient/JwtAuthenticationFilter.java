package com.habittracker.authclient;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private static final String TOKEN_PREFIX = "Bearer ";

    private final AccessTokenValidator accessTokenValidator;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        String accessToken = extractAccessToken(request);
        if (accessToken == null) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            if (accessTokenValidator.validateToken(accessToken)) {
                processValidAccessToken(accessToken);
                filterChain.doFilter(request, response);
            } else {
                handleAuthenticationFailure("Access token is invalid or expired");
            }
        } catch (Exception exception) {
            handleAuthenticationFailure("Access token is invalid or expired");
        }
    }

    private void processValidAccessToken(String accessToken) {
        Authentication authentication = accessTokenValidator.getAuthentication(accessToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private void handleAuthenticationFailure(String message) {
        throw new JwtAuthenticationException(message, HttpStatus.UNAUTHORIZED);
    }

    private String extractAccessToken(HttpServletRequest request) {
        String token = request.getHeader(HttpHeaders.AUTHORIZATION);
        return (StringUtils.hasText(token) && token.startsWith(TOKEN_PREFIX))
                ? token.substring(TOKEN_PREFIX.length()) : null;
    }
}
