package com.tasksphere.auth.controller;

import com.tasksphere.auth.dto.EmailOtpRequest;
import com.tasksphere.auth.dto.LoginRequest;
import com.tasksphere.auth.dto.OtpRequest;
import com.tasksphere.auth.dto.PasswordChangeRequest;
import com.tasksphere.auth.dto.ResetPasswordRequest;
import com.tasksphere.auth.dto.TokenResponse;
import com.tasksphere.auth.service.AuthService;
import jakarta.validation.Valid;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

//New Added
import com.tasksphere.auth.dto.UserCreateRequest;
import com.tasksphere.auth.dto.UserResponse;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout() {
        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }

    @GetMapping("/me")
    public ResponseEntity<com.tasksphere.auth.dto.UserResponse> me(Authentication authentication) {
        return ResponseEntity.ok(authService.getUserByUsername(authentication.getName()));
    }

    @PostMapping("/password/change")
    public ResponseEntity<Map<String, String>> changePassword(Authentication authentication,
            @Valid @RequestBody PasswordChangeRequest request) {
        authService.changePassword(authentication.getName(), request);
        return ResponseEntity.ok(Map.of("message", "Password changed successfully"));
    }

    @PostMapping("/password/forgot")
    public ResponseEntity<Map<String, String>> forgotPassword(@Valid @RequestBody OtpRequest request) {
        authService.requestOtp(request);
        return ResponseEntity.ok(Map.of("status", "OTP sent"));
    }

    @PostMapping("/password/reset/verify")
    public ResponseEntity<Map<String, Boolean>> verifyResetOtp(@RequestBody Map<String, String> payload) {
        boolean verified = authService.verifyOtp(payload.get("username"), "PASSWORD_RESET", payload.get("otp"), false);
        return ResponseEntity.ok(Map.of("verified", verified));
    }

    @PostMapping("/password/reset")
    public ResponseEntity<Map<String, String>> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        authService.resetPassword(request);
        return ResponseEntity.ok(Map.of("message", "Password reset successful"));
    }

    @PostMapping("/user-id/recovery/request")
    public ResponseEntity<Map<String, String>> recoverUserId(@Valid @RequestBody EmailOtpRequest request) {
        authService.requestUserIdRecovery(request.email());
        return ResponseEntity.ok(Map.of("status", "OTP sent"));
    }

    @PostMapping("/user-id/recovery/verify")
    public ResponseEntity<Map<String, Object>> verifyUserRecovery(@RequestBody Map<String, String> payload) {
        String username = authService.verifyUserIdRecovery(payload.get("email"), payload.get("otp"));
        return ResponseEntity.ok(Map.of("verified", true, "username", username));
    }

    // Newly Added Endpoints for User Creation and Retrieval
    @PostMapping("/../admin/users")
    public ResponseEntity<UserResponse> createUser(
            @Valid @RequestBody UserCreateRequest request) {
        return ResponseEntity.status(201)
                .body(authService.createUser(request));
    }
}
