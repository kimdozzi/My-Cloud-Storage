package com.example.deploy.user.service;

import com.example.deploy.security.jwt.util.JWTUtil;
import com.example.deploy.security.oauth2.dto.UserDTO;
import com.example.deploy.user.domain.User;
import com.example.deploy.user.repository.UserRepository;
import org.springframework.stereotype.Service;

@Service
public class AuthService {
    private final JWTUtil jwtUtil;
    private final UserRepository userRepository;

    public AuthService(JWTUtil jwtUtil, UserRepository userRepository) {
        this.jwtUtil = jwtUtil;
        this.userRepository = userRepository;
    }

    public void ValidaterefreshToken(String refreshToken) {
        jwtUtil.validateToken(refreshToken);
    }

    public UserDTO getUser(String refreshToken) {
        String username = jwtUtil.getUsername(refreshToken);

        User user = userRepository.findByUsername(username);
        if (user == null) {
            return null;
        }

        // 사용자 정보를 UserDTO로 변환
        return UserDTO.builder()
                .username(user.getUsername())
                .name(user.getName())
                .role(user.getRole())
                .email(user.getEmail())
                .build();
    }

    public String generateAccessToken(String username, String role) {
        return jwtUtil.generateToken("access", username, role, 600000L);
    }
}
