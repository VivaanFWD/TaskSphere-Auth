package com.tasksphere.auth.controller;

import com.tasksphere.auth.domain.AccountStatus;
import com.tasksphere.auth.dto.UserCreateRequest;
import com.tasksphere.auth.dto.UserResponse;
import com.tasksphere.auth.service.AuthService;
import jakarta.validation.Valid;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/admin")
public class AdminUserController {
    private final AuthService authService;

    public AdminUserController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/users")
    public ResponseEntity<UserResponse> createUser(@Valid @RequestBody UserCreateRequest request) {
        // return ResponseEntity.ok(authService.createUser(request));
        // Newly Added: Return 201 Created status code for user creation
        return ResponseEntity.status(201)
        .body(authService.createUser(request));
    }

    @GetMapping("/users")
    public ResponseEntity<java.util.List<UserResponse>> listUsers() {
        return ResponseEntity.ok(authService.listUsers());
    }

    @GetMapping("/users/{id}")
    public ResponseEntity<UserResponse> getUser(@PathVariable("id") UUID id) {
        return ResponseEntity.ok(authService.getUser(id));
    }

    @GetMapping("/users/by-username/{username}")
    public ResponseEntity<UserResponse> getUserByUsername(@PathVariable("username") String username) {
        return ResponseEntity.ok(authService.getUserByUsername(username));
    }

    @PatchMapping("/users/{id}/status")
    public ResponseEntity<UserResponse> patchStatus(@PathVariable("id") UUID id, @RequestBody Map<String, String> payload) {
        return ResponseEntity.ok(authService.updateStatus(id, AccountStatus.valueOf(payload.get("status"))));
    }

    @PatchMapping("/users/{id}/roles")
    public ResponseEntity<UserResponse> patchRoles(@PathVariable("id") UUID id, @RequestBody Map<String, Set<String>> payload) {
        return ResponseEntity.ok(authService.updateRoles(id, payload.get("roles")));
    }
}
