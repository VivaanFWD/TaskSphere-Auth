package com.tasksphere.auth;

import com.tasksphere.auth.controller.AuthController;
import com.tasksphere.auth.dto.TokenResponse;
import com.tasksphere.auth.service.AuthService;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class AuthControllerIntegrationTest {

    @Test
    void loginShouldSucceed() throws Exception {
        AuthService authService = mock(AuthService.class);
        when(authService.login(org.mockito.ArgumentMatchers.any())).thenReturn(
            new TokenResponse("abc-token", "Bearer", "26MCA0012", "Aarav Sharma", true, Set.of("STUDENT"))
        );

        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(new AuthController(authService)).build();

        mockMvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"26MCA0012\",\"password\":\"26MCA0012\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.username").value("26MCA0012"))
            .andExpect(jsonPath("$.tokenType").value("Bearer"));
    }
}
