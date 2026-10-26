package com.tasksphere.auth.dto;

public record TokenResponse(
    String token,
    String tokenType,
    String username,
    String displayName,
    boolean passwordChangeRequired,
    java.util.Set<String> roles
) {}
