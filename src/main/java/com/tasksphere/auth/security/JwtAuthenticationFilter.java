package com.tasksphere.auth.security;

import com.tasksphere.auth.domain.AccountStatus;
import com.tasksphere.auth.repository.AppUserRepository;
import com.tasksphere.auth.service.JwtTokenService;
import com.tasksphere.auth.web.ApiErrorWriter;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;

public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private final JwtTokenService jwtTokenService;
    private final AppUserRepository userRepository;
    private final ApiErrorWriter apiErrorWriter;

    public JwtAuthenticationFilter(
        JwtTokenService jwtTokenService,
        AppUserRepository userRepository,
        ApiErrorWriter apiErrorWriter
    ) {
        this.jwtTokenService = jwtTokenService;
        this.userRepository = userRepository;
        this.apiErrorWriter = apiErrorWriter;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        return !path.startsWith("/api/v1/") || path.startsWith("/api/v1/admin/");
    }

    @Override
    protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain
    ) throws ServletException, IOException {
        String authorization = request.getHeader("Authorization");
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        try {
            Claims claims = jwtTokenService.parseClaims(authorization.substring(7));
            var user = userRepository.findByUsername(claims.getSubject()).orElse(null);
            if (user == null || user.getStatus() != AccountStatus.ACTIVE) {
                apiErrorWriter.write(request, response, HttpStatus.UNAUTHORIZED,
                    "AUTHENTICATION_FAILED", "Invalid token or inactive account.");
                return;
            }
            String requestPath = request.getRequestURI();
            if (user.isPasswordChangeRequired()
                && !requestPath.endsWith("/api/v1/auth/password/change")
                && !requestPath.endsWith("/api/v1/auth/me")) {
                LOGGER.warn("Blocked authenticated request until required first-login password change: {}", requestPath);
                apiErrorWriter.write(request, response, HttpStatus.FORBIDDEN,
                    "PASSWORD_CHANGE_REQUIRED", "Change the initial password before continuing.");
                return;
            }
            List<SimpleGrantedAuthority> authorities = user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName()))
                .toList();
            var authentication = new UsernamePasswordAuthenticationToken(user.getUsername(), null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (io.jsonwebtoken.JwtException | IllegalArgumentException ex) {
            apiErrorWriter.write(request, response, HttpStatus.UNAUTHORIZED,
                "AUTHENTICATION_FAILED", "Invalid bearer token.");
            return;
        }
        filterChain.doFilter(request, response);
    }
}
