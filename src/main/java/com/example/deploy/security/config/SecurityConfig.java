package com.example.deploy.security.config;

import com.example.deploy.security.jwt.filter.JWTFilter;
import com.example.deploy.security.jwt.util.JWTUtil;
import com.example.deploy.security.oauth2.CustomSuccessHandler;
import com.example.deploy.security.oauth2.service.CustomOAuth2UserService;
import java.util.Arrays;
import java.util.Collections;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private static final String PERMITTED_ROLES[] = {"USER", "ADMIN"};
    private final JWTUtil jwtUtil;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomSuccessHandler customSuccessHandler;

    public SecurityConfig(JWTUtil jwtUtil, CustomOAuth2UserService customOAuth2UserService,
                          CustomSuccessHandler customSuccessHandler) {
        this.jwtUtil = jwtUtil;
        this.customOAuth2UserService = customOAuth2UserService;
        this.customSuccessHandler = customSuccessHandler;
    }

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        // CSRF disable
        http.csrf(AbstractHttpConfigurer::disable)

                // session 상태 : STATELESS
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // CORS 설정
                .cors(corsConfig -> corsConfig.configurationSource(request -> {
                    CorsConfiguration config = new CorsConfiguration();
                    config.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
                    config.setAllowedMethods(Collections.singletonList("*"));
                    config.setAllowCredentials(true);
                    config.setAllowedHeaders(Collections.singletonList("*"));
                    config.setMaxAge(3600L);

                    config.setExposedHeaders(Arrays.asList("Set-Cookie", "Authorization", "access", "refresh"));
                    return config;
                }))

                // http 베이직 인증 방식 disable
                .httpBasic(HttpBasicConfigurer::disable)

                // 로그인 방식 disable
                .formLogin(FormLoginConfigurer::disable)

                // OAuth2
                .oauth2Login((oauth2) -> oauth2
                        .userInfoEndpoint((userInfoEndpointConfig) -> userInfoEndpointConfig
                                .userService(customOAuth2UserService))
                        .successHandler(customSuccessHandler))
                .addFilterAfter(new JWTFilter(jwtUtil), OAuth2LoginAuthenticationFilter.class)

                // JWT Token (access & refresh)
//                .addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class)
//                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil, redisService),
//                        UsernamePasswordAuthenticationFilter.class)

                // authentication & authorization
                .authorizeHttpRequests(request ->
                        request
                                .requestMatchers("/reissue", "/login/**", "/auth/**", "/test").permitAll()
                                .anyRequest().hasAnyRole(PERMITTED_ROLES));

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
