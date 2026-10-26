package com.tasksphere.auth.dto;

import com.tasksphere.auth.domain.AccountStatus;
import java.util.Set;
import java.util.UUID;

public record UserResponse(
    UUID id,
    String username,
    String firstName,
    String lastName,
    String email,
    AccountStatus status,
    boolean passwordChangeRequired,
    Set<String> roles
) {}
