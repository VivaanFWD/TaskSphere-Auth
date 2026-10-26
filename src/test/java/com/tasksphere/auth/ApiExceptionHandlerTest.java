package com.tasksphere.auth;

import com.tasksphere.auth.controller.ApiExceptionHandler;
import com.tasksphere.auth.exception.RateLimitExceededException;
import com.tasksphere.auth.web.ApiErrorWriter;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;

class ApiExceptionHandlerTest {
    private final ApiExceptionHandler handler = new ApiExceptionHandler();
    private final MockHttpServletRequest request = new MockHttpServletRequest();

    @Test
    void onlyRateLimitFailuresReturnTooManyRequests() {
        assertEquals(HttpStatus.CONFLICT,
            handler.state(new IllegalStateException("Account is not active"), request).getStatusCode());
        assertEquals(HttpStatus.TOO_MANY_REQUESTS,
            handler.rateLimit(new RateLimitExceededException("Wait before retrying"), request).getStatusCode());
    }

    @Test
    void filterErrorsUseTheSharedJsonErrorShape() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        new ApiErrorWriter().write(request, response, HttpStatus.UNAUTHORIZED,
            "AUTHENTICATION_REQUIRED", "Valid authentication is required.");

        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
        assertTrue(response.getContentType().startsWith("application/json"));
        assertTrue(response.getContentAsString().contains("\"code\":\"AUTHENTICATION_REQUIRED\""));
        assertTrue(response.getContentAsString().contains("\"timestamp\""));
    }
}
