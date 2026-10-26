package com.tasksphere.auth.dto;

import jakarta.validation.constraints.NotBlank;

public record ResetPasswordRequest(
    @NotBlank String username,
    @NotBlank String otp,
    @NotBlank String newPassword
) {}
