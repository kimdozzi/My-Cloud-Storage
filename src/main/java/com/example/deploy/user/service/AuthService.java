package com.example.deploy.user.service;

import com.example.deploy.redis.service.RedisService;
import com.example.deploy.security.jwt.util.JWTUtil;
import com.example.deploy.security.oauth2.dto.UserDTO;
import com.example.deploy.user.domain.User;
import com.example.deploy.user.repository.UserRepository;
import jakarta.servlet.http.Cookie;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {
    private final JWTUtil jwtUtil;
    private final UserRepository userRepository;
    private final RedisService redisService;

    public AuthService(JWTUtil jwtUtil, UserRepository userRepository, RedisService redisService) {
        this.jwtUtil = jwtUtil;
        this.userRepository = userRepository;
        this.redisService = redisService;
    }

    public void ValidateToken(String token) {
        jwtUtil.validateToken(token);
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

    @Transactional
    public Cookie generateRefreshToken(String username, String role) {
        String refresh = jwtUtil.generateToken("refresh", username, role, 56800000L);
        redisService.saveRefreshToken(username, refresh, 60*60*60);
        return createCookie("refresh", refresh);
    }

    @Transactional
    public void deleteRefreshToken(String username) {
        redisService.deleteRefreshToken(username);
    }

    private Cookie createCookie(String key, String value) {
        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(60 * 60 * 60);
        //cookie.setSecure(true);
        cookie.setPath("/");
        //cookie.setHttpOnly(true);

        return cookie;
    }


}