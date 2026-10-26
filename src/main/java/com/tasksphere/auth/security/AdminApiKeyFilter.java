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
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

public class AdminApiKeyFilter extends OncePerRequestFilter {
    private final String serviceKey;
    private final ApiErrorWriter apiErrorWriter;

    public AdminApiKeyFilter(String serviceKey, ApiErrorWriter apiErrorWriter) {
        this.serviceKey = serviceKey;
        this.apiErrorWriter = apiErrorWriter;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        return !path.startsWith("/api/v1/admin/");
    }

    @Override
    protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain
    ) throws ServletException, IOException {
        String supplied = request.getHeader("X-Admin-API-Key");
        if (serviceKey.isBlank() || supplied == null
            || !MessageDigest.isEqual(
                serviceKey.getBytes(StandardCharsets.UTF_8),
                supplied.getBytes(StandardCharsets.UTF_8))) {
            apiErrorWriter.write(request, response, HttpStatus.UNAUTHORIZED,
                "SERVICE_AUTHENTICATION_FAILED", "Valid service credentials are required.");
            return;
        }
        var authentication = new UsernamePasswordAuthenticationToken(
            "tasksphere-service",
            null,
            AuthorityUtils.createAuthorityList("ROLE_ADMIN")
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        filterChain.doFilter(request, response);
    }
}
