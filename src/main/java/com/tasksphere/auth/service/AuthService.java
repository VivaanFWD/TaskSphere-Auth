package com.tasksphere.auth.service;

import com.tasksphere.auth.domain.AccountStatus;
import com.tasksphere.auth.domain.AppUser;
import com.tasksphere.auth.domain.OtpChallenge;
import com.tasksphere.auth.domain.Role;
import com.tasksphere.auth.exception.DuplicateAccountException;
import com.tasksphere.auth.exception.RateLimitExceededException;
import com.tasksphere.auth.dto.LoginRequest;
import com.tasksphere.auth.dto.OtpRequest;
import com.tasksphere.auth.dto.PasswordChangeRequest;
import com.tasksphere.auth.dto.ResetPasswordRequest;
import com.tasksphere.auth.dto.TokenResponse;
import com.tasksphere.auth.dto.UserCreateRequest;
import com.tasksphere.auth.dto.UserResponse;
import com.tasksphere.auth.repository.AppUserRepository;
import com.tasksphere.auth.repository.OtpChallengeRepository;
import com.tasksphere.auth.repository.RoleRepository;
import jakarta.persistence.EntityNotFoundException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int OTP_LENGTH = 6;
    private static final long OTP_TTL_SECONDS = 300;

    private final AppUserRepository appUserRepository;
    private final RoleRepository roleRepository;
    private final OtpChallengeRepository otpChallengeRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenService jwtTokenService;
    private final JavaMailSender mailSender;
    private final String mailFrom;

    public AuthService(AppUserRepository appUserRepository,
                      RoleRepository roleRepository,
                      OtpChallengeRepository otpChallengeRepository,
                      PasswordEncoder passwordEncoder,
                      AuthenticationManager authenticationManager,
                      JwtTokenService jwtTokenService,
                      JavaMailSender mailSender,
                      @Value("${app.mail-from:no-reply@localhost}") String mailFrom) {
        this.appUserRepository = appUserRepository;
        this.roleRepository = roleRepository;
        this.otpChallengeRepository = otpChallengeRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtTokenService = jwtTokenService;
        this.mailSender = mailSender;
        this.mailFrom = mailFrom;
    }

    @Transactional
    public TokenResponse login(LoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(request.username(), request.password())
        );
        AppUser user = appUserRepository.findByUsername(request.username())
            .orElseThrow(() -> new EntityNotFoundException("User not found"));

        if (user.getStatus() != AccountStatus.ACTIVE) {
            throw new IllegalStateException("Account is not active");
        }

        user.setLastLoginAt(Instant.now());
        appUserRepository.save(user);
        String token = jwtTokenService.generateToken(user);
        return new TokenResponse(
            token,
            "Bearer",
            user.getUsername(),
            user.getFirstName() + " " + user.getLastName(),
            user.isPasswordChangeRequired(),
            user.getRoles().stream().map(Role::getName).collect(Collectors.toSet())
        );
    }

    @Transactional(readOnly = true)
    public UserResponse getUserByUsername(String username) {
        AppUser user = appUserRepository.findByUsername(username)
            .orElseThrow(() -> new EntityNotFoundException("User not found"));
        return mapToResponse(user);
    }

    @Transactional
    public UserResponse createUser(UserCreateRequest request) {
        if (appUserRepository.existsByUsername(request.username()) || appUserRepository.existsByEmail(request.email())) {
            throw new DuplicateAccountException("Username or email already exists");
        }
        if (request.password().length() < 8) {
            throw new IllegalArgumentException("Initial password must contain at least 8 characters");
        }
        AppUser user = new AppUser();
        user.setUsername(request.username());
        user.setFirstName(request.firstName());
        user.setLastName(request.lastName());
        user.setEmail(request.email());
        user.setPasswordHash(passwordEncoder.encode(request.password()));
        user.setPasswordChangeRequired(true);

        Set<Role> roles = request.roles() == null || request.roles().isEmpty()
            ? Set.of(roleRepository.findByName("USER").orElseGet(() -> roleRepository.save(new Role("USER", "Default role"))))
            : request.roles().stream()
                .map(roleName -> roleRepository.findByName(roleName)
                    .orElseGet(() -> roleRepository.save(new Role(roleName, "Provisioned role"))))
                .collect(Collectors.toSet());
        user.setRoles(roles);
        return mapToResponse(appUserRepository.save(user));
    }

    @Transactional
    public void changePassword(String username, PasswordChangeRequest request) {
        if (!request.newPassword().equals(request.confirmPassword())) {
            throw new IllegalArgumentException("Passwords do not match");
        }
        if (request.newPassword().length() < 12) {
            throw new IllegalArgumentException("New password must contain at least 12 characters");
        }
        AppUser user = appUserRepository.findByUsername(username)
            .orElseThrow(() -> new EntityNotFoundException("User not found"));
        if (!passwordEncoder.matches(request.currentPassword(), user.getPasswordHash())) {
            throw new IllegalArgumentException("Current password is incorrect");
        }
        user.setPasswordHash(passwordEncoder.encode(request.newPassword()));
        user.setPasswordChangeRequired(false);
        appUserRepository.save(user);
    }

    @Transactional
    public void requestOtp(OtpRequest request) {
        AppUser user = appUserRepository.findByUsername(request.username())
            .orElseThrow(() -> new EntityNotFoundException("User not found"));
        issueOtp(user, request.purpose());
    }

    @Transactional
    public void requestUserIdRecovery(String email) {
        AppUser user = appUserRepository.findByEmail(email)
            .orElseThrow(() -> new EntityNotFoundException("Account not found"));
        issueOtp(user, "USER_ID_RECOVERY");
    }

    @Transactional
    public String verifyUserIdRecovery(String email, String otp) {
        AppUser user = appUserRepository.findByEmail(email)
            .orElseThrow(() -> new EntityNotFoundException("Account not found"));
        if (!verifyOtp(user.getUsername(), "USER_ID_RECOVERY", otp, true)) {
            throw new IllegalArgumentException("Invalid or expired OTP");
        }
        return user.getUsername();
    }

    private void issueOtp(AppUser user, String purpose) {
        if (!purpose.equals("PASSWORD_RESET") && !purpose.equals("USER_ID_RECOVERY")) {
            throw new IllegalArgumentException("Unsupported OTP purpose");
        }
        String code = generateNumericOtp();
        OtpChallenge challenge = otpChallengeRepository.findTopByPurposeAndIdentifierOrderByCreatedAtDesc(purpose, user.getUsername())
            .orElse(null);
        if (challenge != null && challenge.getCreatedAt().plusSeconds(30).isAfter(Instant.now())) {
            throw new RateLimitExceededException("Please wait before requesting another code");
        }
        if (challenge != null && challenge.getUsedAt() == null && challenge.getExpiresAt().isAfter(Instant.now())) {
            challenge.setUsedAt(Instant.now());
            otpChallengeRepository.save(challenge);
        }
        OtpChallenge newChallenge = new OtpChallenge();
        newChallenge.setPurpose(purpose);
        newChallenge.setIdentifier(user.getUsername());
        newChallenge.setCodeHash(passwordEncoder.encode(code));
        newChallenge.setExpiresAt(Instant.now().plusSeconds(OTP_TTL_SECONDS));
        otpChallengeRepository.save(newChallenge);
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(mailFrom);
        message.setTo(user.getEmail());
        message.setSubject("Your account verification code");
        message.setText("Your one-time verification code is " + code + ". It expires in five minutes and can only be used once.");
        mailSender.send(message);
    }

    @Transactional
    public boolean verifyOtp(String username, String purpose, String otp) {
        return verifyOtp(username, purpose, otp, true);
    }

    @Transactional
    public boolean verifyOtp(String username, String purpose, String otp, boolean consume) {
        AppUser user = appUserRepository.findByUsername(username)
            .orElseThrow(() -> new EntityNotFoundException("User not found"));
        OtpChallenge challenge = otpChallengeRepository.findTopByPurposeAndIdentifierOrderByCreatedAtDesc(purpose, user.getUsername())
            .orElseThrow(() -> new EntityNotFoundException("OTP challenge not found"));
        if (challenge.getUsedAt() != null || challenge.getExpiresAt().isBefore(Instant.now()) || challenge.getAttemptCount() >= 5) {
            return false;
        }
        if (!passwordEncoder.matches(otp, challenge.getCodeHash())) {
            challenge.setAttemptCount(challenge.getAttemptCount() + 1);
            if (challenge.getAttemptCount() >= 5) {
                challenge.setUsedAt(Instant.now());
            }
            otpChallengeRepository.save(challenge);
            return false;
        }
        if (consume) {
            challenge.setUsedAt(Instant.now());
            otpChallengeRepository.save(challenge);
        }
        return true;
    }

    @Transactional
    public void resetPassword(ResetPasswordRequest request) {
        if (request.newPassword().length() < 12) {
            throw new IllegalArgumentException("New password must contain at least 12 characters");
        }
        if (!verifyOtp(request.username(), "PASSWORD_RESET", request.otp(), true)) {
            throw new IllegalArgumentException("Invalid or expired OTP");
        }
        AppUser user = appUserRepository.findByUsername(request.username())
            .orElseThrow(() -> new EntityNotFoundException("User not found"));
        user.setPasswordHash(passwordEncoder.encode(request.newPassword()));
        user.setPasswordChangeRequired(false);
        appUserRepository.save(user);
    }

    @Transactional
    public UserResponse updateStatus(UUID userId, AccountStatus status) {
        AppUser user = appUserRepository.findById(userId)
            .orElseThrow(() -> new EntityNotFoundException("User not found"));
        user.setStatus(status);
        return mapToResponse(appUserRepository.save(user));
    }

    @Transactional
    public UserResponse updateRoles(UUID userId, Set<String> roleNames) {
        AppUser user = appUserRepository.findById(userId)
            .orElseThrow(() -> new EntityNotFoundException("User not found"));
        Set<Role> roles = roleNames.stream()
            .map(name -> roleRepository.findByName(name)
                .orElseGet(() -> roleRepository.save(new Role(name, "Provisioned role"))))
            .collect(Collectors.toSet());
        user.setRoles(roles);
        return mapToResponse(appUserRepository.save(user));
    }

    @Transactional(readOnly = true)
    public List<UserResponse> listUsers() {
        return appUserRepository.findAll().stream().map(this::mapToResponse).toList();
    }

    @Transactional(readOnly = true)
    public UserResponse getUser(UUID id) {
        return mapToResponse(appUserRepository.findById(id).orElseThrow(() -> new EntityNotFoundException("User not found")));
    }

    private UserResponse mapToResponse(AppUser user) {
        return new UserResponse(
            user.getId(),
            user.getUsername(),
            user.getFirstName(),
            user.getLastName(),
            user.getEmail(),
            user.getStatus(),
            user.isPasswordChangeRequired(),
            user.getRoles().stream().map(Role::getName).collect(Collectors.toSet())
        );
    }

    private String generateNumericOtp() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < OTP_LENGTH; i++) {
            sb.append(RANDOM.nextInt(10));
        }
        return sb.toString();
    }
}
