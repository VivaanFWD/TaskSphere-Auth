package com.tasksphere.auth.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import com.tasksphere.auth.web.ApiErrorWriter;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;

public class ClientApiKeyFilter extends OncePerRequestFilter {
    private final String clientId;
    private final String clientSecret;
    private final ApiErrorWriter apiErrorWriter;

    public ClientApiKeyFilter(String clientId, String clientSecret, ApiErrorWriter apiErrorWriter) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.apiErrorWriter = apiErrorWriter;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        return !(path.equals("/api/v1/auth/login")
            || path.startsWith("/api/v1/auth/password/forgot")
            || path.startsWith("/api/v1/auth/password/reset")
            || path.startsWith("/api/v1/auth/user-id/recovery"));
    }

    @Override
    protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain
    ) throws ServletException, IOException {
        String suppliedClientId = request.getHeader("X-Client-ID");
        String suppliedSecret = request.getHeader("X-Client-Secret");
        if (!secureEquals(clientId, suppliedClientId) || !secureEquals(clientSecret, suppliedSecret)) {
            apiErrorWriter.write(request, response, HttpStatus.UNAUTHORIZED,
                "CLIENT_AUTHENTICATION_FAILED", "Valid client credentials are required.");
            return;
        }
        filterChain.doFilter(request, response);
    }

    private boolean secureEquals(String expected, String supplied) {
        return supplied != null && MessageDigest.isEqual(
            expected.getBytes(StandardCharsets.UTF_8),
            supplied.getBytes(StandardCharsets.UTF_8)
        );
    }
}
