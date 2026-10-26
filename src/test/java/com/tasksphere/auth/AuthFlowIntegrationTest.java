package com.tasksphere.auth;

import com.tasksphere.auth.domain.AccountStatus;
import com.tasksphere.auth.domain.AppUser;
import com.tasksphere.auth.domain.Role;
import com.tasksphere.auth.repository.AppUserRepository;
import com.tasksphere.auth.repository.RoleRepository;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthFlowIntegrationTest {
    private static final Pattern TOKEN_PATTERN = Pattern.compile("\"token\":\"([^\"]+)\"");

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AppUserRepository appUserRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void setUp() {
        appUserRepository.deleteAll();
        roleRepository.deleteAll();

        AppUser user = new AppUser();
        user.setUsername("office-test");
        user.setPasswordHash(passwordEncoder.encode("Initial-Password-2026"));
        user.setFirstName("Test");
        user.setLastName("Office");
        user.setEmail("office-test@example.test");
        user.setStatus(AccountStatus.ACTIVE);
        user.setPasswordChangeRequired(true);
        user.getRoles().add(roleRepository.save(new Role("ACADEMIC_OFFICE", "Test workspace role")));
        appUserRepository.save(user);
    }

    @Test
    void loginPasswordChangeAndFrozenAccountFlow() throws Exception {
        MvcResult loginResult = mockMvc.perform(post("/api/v1/auth/login")
                .header("X-Client-ID", "tasksphere-app")
                .header("X-Client-Secret", "local-only-client-secret-change-before-deploying")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"office-test\",\"password\":\"Initial-Password-2026\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.passwordChangeRequired").value(true))
            .andReturn();

        String initialToken = extractToken(loginResult);
        mockMvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer " + initialToken))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.username").value("office-test"));

        mockMvc.perform(post("/api/v1/auth/password/change")
                .header("Authorization", "Bearer " + initialToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"currentPassword\":\"Initial-Password-2026\",\"newPassword\":\"New-Password-2026-long\",\"confirmPassword\":\"New-Password-2026-long\"}"))
            .andExpect(status().isOk());

        MvcResult changedLogin = mockMvc.perform(post("/api/v1/auth/login")
                .header("X-Client-ID", "tasksphere-app")
                .header("X-Client-Secret", "local-only-client-secret-change-before-deploying")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"office-test\",\"password\":\"New-Password-2026-long\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.passwordChangeRequired").value(false))
            .andReturn();

        String activeToken = extractToken(changedLogin);
        AppUser user = appUserRepository.findByUsername("office-test").orElseThrow();
        user.setStatus(AccountStatus.FROZEN);
        appUserRepository.save(user);

        mockMvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer " + activeToken))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void loginRequiresRegisteredClientCredentials() throws Exception {
        mockMvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"office-test\",\"password\":\"Initial-Password-2026\"}"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void passwordChangeEnforcesMinimumLength() throws Exception {
        MvcResult loginResult = mockMvc.perform(post("/api/v1/auth/login")
                .header("X-Client-ID", "tasksphere-app")
                .header("X-Client-Secret", "local-only-client-secret-change-before-deploying")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"office-test\",\"password\":\"Initial-Password-2026\"}"))
            .andExpect(status().isOk())
            .andReturn();
        String token = extractToken(loginResult);

        mockMvc.perform(post("/api/v1/auth/password/change")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"currentPassword\":\"Initial-Password-2026\",\"newPassword\":\"short\",\"confirmPassword\":\"short\"}"))
            .andExpect(status().isBadRequest());
    }

    @Test
    void adminProvisioningRequiresServiceKey() throws Exception {
        mockMvc.perform(post("/api/v1/admin/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"new-user\",\"firstName\":\"New\",\"lastName\":\"User\",\"email\":\"new@example.test\",\"password\":\"Initial-Password-2026\",\"roles\":[\"STUDENT\"]}"))
            .andExpect(status().isUnauthorized());
    }

    private String extractToken(MvcResult result) throws Exception {
        Matcher matcher = TOKEN_PATTERN.matcher(result.getResponse().getContentAsString());
        if (!matcher.find()) {
            throw new AssertionError("Login response did not contain a bearer token");
        }
        return matcher.group(1);
    }
}
