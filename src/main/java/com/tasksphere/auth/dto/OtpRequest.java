package com.tasksphere.auth.dto;

import jakarta.validation.constraints.NotBlank;

public record OtpRequest(
    @NotBlank String username,
    @NotBlank String purpose
) {}
