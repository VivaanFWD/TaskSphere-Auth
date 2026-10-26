package com.tasksphere.auth.service;

import com.tasksphere.auth.config.JwtProperties;
import com.tasksphere.auth.domain.AppUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import javax.crypto.SecretKey;
import org.springframework.stereotype.Service;

@Service
public class JwtTokenService {
    private final JwtProperties properties;
    private SecretKey signingKey;

    public JwtTokenService(JwtProperties properties) {
        this.properties = properties;
    }

    @PostConstruct
    public void init() {
        signingKey = Keys.hmacShaKeyFor(properties.getSecret().getBytes(StandardCharsets.UTF_8));
    }

    public String generateToken(AppUser user) {
        Instant now = Instant.now();
        Instant expiry = now.plusSeconds(properties.getExpirationMinutes() * 60L);
        return Jwts.builder()
            .issuer(properties.getIssuer())
            .audience().add(properties.getAudience()).and()
            .subject(user.getUsername())
            .id(UUID.randomUUID().toString())
            .issuedAt(Date.from(now))
            .expiration(Date.from(expiry))
            .claim("userId", user.getId().toString())
            .claim("roles", user.getRoles().stream().map(role -> role.getName()).toList())
            .signWith(signingKey)
            .compact();
    }

    public Claims parseClaims(String token) {
        Claims claims = Jwts.parser()
            .verifyWith(signingKey)
            .build()
            .parseSignedClaims(token)
            .getPayload();
        if (!properties.getIssuer().equals(claims.getIssuer())
            || claims.getAudience() == null
            || !claims.getAudience().contains(properties.getAudience())) {
            throw new io.jsonwebtoken.JwtException("Token issuer or audience is invalid");
        }
        return claims;
    }
}
