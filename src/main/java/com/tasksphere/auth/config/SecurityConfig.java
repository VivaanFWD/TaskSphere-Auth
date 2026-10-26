package com.tasksphere.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import com.tasksphere.auth.repository.AppUserRepository;
import com.tasksphere.auth.service.JwtTokenService;
import com.tasksphere.auth.security.AdminApiKeyFilter;
import com.tasksphere.auth.security.ClientApiKeyFilter;
import com.tasksphere.auth.security.JwtAuthenticationFilter;
import com.tasksphere.auth.web.ApiErrorWriter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(AppUserRepository appUserRepository) {
        return username -> appUserRepository.findByUsername(username)
            .map(user -> org.springframework.security.core.userdetails.User.withUsername(user.getUsername())
                .password(user.getPasswordHash())
                .authorities(user.getRoles().stream().map(role -> "ROLE_" + role.getName()).toArray(String[]::new))
                .accountLocked(user.getStatus() != com.tasksphere.auth.domain.AccountStatus.ACTIVE)
                .disabled(user.getStatus() == com.tasksphere.auth.domain.AccountStatus.DEACTIVATED)
                .build())
            .orElseThrow(() -> new org.springframework.security.core.userdetails.UsernameNotFoundException("User not found"));
    }

    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return new ProviderManager(provider);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
        HttpSecurity http,
        JwtAuthenticationFilter jwtAuthenticationFilter,
        AdminApiKeyFilter adminApiKeyFilter,
        ClientApiKeyFilter clientApiKeyFilter,
        ApiErrorWriter apiErrorWriter
    ) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .cors(cors -> cors.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(
                    "/api/v1/auth/login",
                    "/api/v1/auth/password/forgot",
                    "/api/v1/auth/password/reset",
                    "/api/v1/auth/password/reset/verify",
                    "/api/v1/auth/user-id/recovery/**",
                    "/error",
                    "/actuator/health",
                    "/v3/api-docs/**",
                    "/swagger-ui/**",
                    "/swagger-ui.html"
                ).permitAll()
                .anyRequest().authenticated())
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint((request, response, exception) ->
                    apiErrorWriter.write(request, response,
                        org.springframework.http.HttpStatus.UNAUTHORIZED,
                        "AUTHENTICATION_REQUIRED", "Valid authentication is required."))
                .accessDeniedHandler((request, response, exception) ->
                    apiErrorWriter.write(request, response,
                        org.springframework.http.HttpStatus.FORBIDDEN,
                        "ACCESS_DENIED", "You do not have permission to access this resource.")))
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .addFilterBefore(clientApiKeyFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(adminApiKeyFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public ClientApiKeyFilter clientApiKeyFilter(
        @Value("${security.client.id:tasksphere-app}") String clientId,
        @Value("${security.client.secret:local-only-client-secret-change-before-deploying}") String clientSecret,
        ApiErrorWriter apiErrorWriter
    ) {
        return new ClientApiKeyFilter(clientId, clientSecret, apiErrorWriter);
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(
        JwtTokenService jwtTokenService,
        AppUserRepository appUserRepository,
        ApiErrorWriter apiErrorWriter
    ) {
        return new JwtAuthenticationFilter(jwtTokenService, appUserRepository, apiErrorWriter);
    }

    @Bean
    public AdminApiKeyFilter adminApiKeyFilter(
        @Value("${security.admin.api-key:}") String serviceKey,
        ApiErrorWriter apiErrorWriter
    ) {
        return new AdminApiKeyFilter(serviceKey, apiErrorWriter);
    }

    @Bean
    public FilterRegistrationBean<ClientApiKeyFilter> clientFilterRegistration(ClientApiKeyFilter filter) {
        return disableServletRegistration(filter);
    }

    @Bean
    public FilterRegistrationBean<AdminApiKeyFilter> adminFilterRegistration(AdminApiKeyFilter filter) {
        return disableServletRegistration(filter);
    }

    @Bean
    public FilterRegistrationBean<JwtAuthenticationFilter> jwtFilterRegistration(JwtAuthenticationFilter filter) {
        return disableServletRegistration(filter);
    }

    private <T extends jakarta.servlet.Filter> FilterRegistrationBean<T> disableServletRegistration(T filter) {
        FilterRegistrationBean<T> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }
}
