package com.example.deploy.security.oauth2.handler;

import com.example.deploy.redis.service.RedisService;
import com.example.deploy.security.jwt.util.JWTUtil;
import com.example.deploy.security.oauth2.dto.CustomOAuth2User;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class CustomSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JWTUtil jwtUtil;
    private final RedisService redisService;

    public CustomSuccessHandler(JWTUtil jwtUtil, RedisService redisService) {
        this.jwtUtil = jwtUtil;
        this.redisService = redisService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        // OAuth2User 유저 정보 받아오기
        CustomOAuth2User customUserDetails = (CustomOAuth2User) authentication.getPrincipal();

        String username = customUserDetails.getUsername();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();

        // 토큰 생성
        String refresh = jwtUtil.generateToken("refresh", username, role, 86400000L);

        // Redis에 refresh 토큰 저장
        redisService.saveRefreshToken(username, refresh, 60 * 60 * 60);

        // 로그인 성공한 유저 정보와 토큰 정보
        log.info("CustomSuccessHandler.onAuthenticationSuccess");
        log.info("Username : " + username);
        log.info("role : " + role);
        log.info("refresh : " + refresh);

        response.addCookie(createCookie("refresh", refresh));
        response.sendRedirect("http://localhost:3000/success");
    }

    private Cookie createCookie(String key, String value) {
        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(60 * 60 * 60);
        //cookie.setSecure(true);
        cookie.setPath("/");
        // cookie.setHttpOnly(true);

        return cookie;
    }
}