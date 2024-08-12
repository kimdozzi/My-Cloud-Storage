package com.example.deploy.user.controller;

import static com.example.deploy.global.util.SuccessCode.JOIN_SUCCESS;
import static com.example.deploy.global.util.SuccessCode.SUCCESS;

import com.example.deploy.global.response.SingleResponse;
import com.example.deploy.global.util.SuccessCode;
import com.example.deploy.security.jwt.util.JWTUtil;
import com.example.deploy.security.oauth2.dto.CustomOAuth2User;
import com.example.deploy.security.oauth2.dto.UserDTO;
import com.example.deploy.security.oauth2.service.CustomOAuth2UserService;
import com.example.deploy.user.domain.User;
import com.example.deploy.user.dto.JoinRequest;
import com.example.deploy.user.dto.JoinResponse;
import com.example.deploy.user.dto.LogoutResponse;
import com.example.deploy.user.dto.UserLogoutRequest;
import com.example.deploy.user.service.AuthService;
import com.example.deploy.user.service.UserService;
import com.nimbusds.openid.connect.sdk.LogoutRequest;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    private final UserService userService;
    private final AuthService authService;

    public AuthController(UserService userService, AuthService authService) {
        this.userService = userService;
        this.authService = authService;
    }

    @GetMapping("/admin")
    @PreAuthorize("isAuthenticated() and hasRole('ROLE_ADMIN')")
    public String adminP() {
        return "admin Controller";
    }

    @PostMapping("/join")
    public ResponseEntity<SingleResponse<JoinResponse>> joinController(@RequestBody JoinRequest joinRequest) {
        JoinResponse joinResponse = userService.createUser(joinRequest);
        return ResponseEntity.ok().body(
                new SingleResponse<>(JOIN_SUCCESS.getStatus(), JOIN_SUCCESS.getMessage(), joinResponse)
        );
    }

    @PostMapping("/logout")
    public ResponseEntity<SingleResponse<LogoutResponse>> logoutController(@RequestBody UserLogoutRequest userLogoutRequest,
                                                                           HttpServletRequest httpServletRequest) {

        // header에서 refresh 존재 여부 확인
        String header = httpServletRequest.getHeader("refresh");

        // refresh 만료 여부 확인

        // DB에 저장되어 있는지 확인

        // 로그아웃 진행
        // 1. DB에서 refresh 제거
        // 2. refresh token 쿠키 값 0

        return null;
    }

    @PostMapping("/auth/token/refresh")
    public ResponseEntity<UserDTO> refreshAccessToken(@RequestHeader("refresh") String refreshToken) {

        // refreshToken 검증
        authService.ValidaterefreshToken(refreshToken);

        // refreshToken에서 사용자 정보 추출
        UserDTO user = authService.getUser(refreshToken);

        // Access Token 발급
        String accessToken = authService.generateAccessToken(user.username(), user.role());

        // 헤더에 새로운 accessToken과 refreshToken을 추가하여 응답
        HttpHeaders headers = new HttpHeaders();
        headers.add("access", accessToken);

        return ResponseEntity.ok().headers(headers).body(user);
    }
}