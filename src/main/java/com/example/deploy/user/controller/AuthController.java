package com.example.deploy.user.controller;

import com.example.deploy.security.oauth2.dto.UserDTO;
import com.example.deploy.user.service.AuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.OK)
    public void logoutController(@RequestHeader("access") String accessToken, HttpServletRequest request,
                                 HttpServletResponse response) {
        // refresh token 쿠키 값 0
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("refresh".equals(cookie.getName())) {
                    cookie.setPath("/");
                    cookie.setMaxAge(0);
                    response.addCookie(cookie);
                    break;
                }
            }
        }
        // access에서 사용자 정보 추출
        UserDTO user = authService.getUser(accessToken);

        // Redis 에서 refresh 제거
        authService.deleteRefreshToken(user.username());
    }

    // 초기 발급
    @PostMapping("/auth/token/refresh")
    public ResponseEntity<UserDTO> refreshAccessToken(@RequestHeader("refresh") String refresh,
                                                      HttpServletResponse response) {
        /*
         * 실제로는 httpOnly를 통해 refresh token을 쿠키에서 확인하고, Access & Refresh 를 발급하는 게 정상.
         * 하지만, 쿠키로 전달한 refresh를 클라이언트에서 정상적으로 받고, 동일한 데이터를 보내는 지 확인을 위해 이와 같이 코드를 작성.
         * 응답받은 refresh를 검증하고, RTR 방식으로 access & refresh를 둘 다 발급.
         * */

        authService.ValidaterefreshToken(refresh);
        UserDTO user = authService.getUser(refresh);

        String accessToken = authService.generateAccessToken(user.username(), user.role());

        // 헤더에 새로운 accessToken을 추가하여 응답
        HttpHeaders headers = new HttpHeaders();
        headers.add("access", accessToken);
        return ResponseEntity.ok().headers(headers).body(user);
    }

    // Access Token 만료 시 재발급 요청
    @PostMapping("/auth/token/access")
    public ResponseEntity<UserDTO> AccessToken(@RequestHeader("access") String access,
                                                      HttpServletResponse response) {
        UserDTO user = authService.getUser(access);

        // Access & Refresh Token 발급 (RTR)
        String accessToken = authService.generateAccessToken(user.username(), user.role());
        Cookie refreshTokenCookie = authService.generateRefreshToken(user.username(), user.role());

        // 헤더에 accessToken과 refreshToken을 추가하여 응답
        response.setHeader("access", accessToken);
        response.addCookie(refreshTokenCookie);
        return ResponseEntity.ok().body(user);
    }
}