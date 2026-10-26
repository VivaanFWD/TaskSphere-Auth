package com.tasksphere.auth.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI authOpenApi(@Value("${openapi.server-url:http://localhost:8081}") String serverUrl) {
        return new OpenAPI()
            .info(new Info()
                .title("TaskSphere Auth Service API")
                .description("Reusable authentication and identity management API")
                .version("1.0.0"));
    }
}
