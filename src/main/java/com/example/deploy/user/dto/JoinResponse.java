package com.example.deploy.user.dto;

import lombok.Builder;

@Builder
public record JoinResponse (
        String username,
        String role
) {
    private static JoinResponse of(String username, String role) {
        return JoinResponse.builder()
                .username(username)
                .role(role).build();
    }
}
