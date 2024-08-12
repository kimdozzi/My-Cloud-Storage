package com.example.deploy.security.oauth2.dto;

import lombok.Builder;

@Builder
public record UserDTO (
        String role,
        String name,
        String username,
        String email
){
    public static UserDTO of(String role, String name, String username, String email) {
        return UserDTO.builder()
                .role(role)
                .name(name)
                .username(username)
                .email(email)
                .build();
    }
}
