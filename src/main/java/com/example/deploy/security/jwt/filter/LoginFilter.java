//package com.example.deploy.security.jwt.filter;
//
//import com.example.deploy.redis.service.RedisService;
//import com.example.deploy.security.jwt.util.JWTUtil;
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.Cookie;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import java.io.IOException;
//import java.util.Collection;
//import java.util.Iterator;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.http.HttpStatus;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.core.GrantedAuthority;
//import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
//
//@Slf4j
//public class LoginFilter extends UsernamePasswordAuthenticationFilter {
//
//    private final AuthenticationManager authenticationManager;
//    private final JWTUtil jwtUtil;
//    private final RedisService redisService;
//
//    public LoginFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil, RedisService redisService) {
//        this.authenticationManager = authenticationManager;
//        this.jwtUtil = jwtUtil;
//        this.redisService = redisService;
//    }
//
//    @Override
//    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
//            throws AuthenticationException {
//
//        String username = obtainUsername(request);
//        String password = obtainPassword(request);
//
//        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
//                username, password, null);
//
//        return authenticationManager.authenticate(authToken);
//    }
//
//    @Override
//    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
//                                            Authentication authentication) throws IOException, ServletException {
//
//        // 유저 정보 받아오기
//        String username = authentication.getName();
//
//        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
//        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
//        GrantedAuthority auth = iterator.next();
//        String role = auth.getAuthority();
//
//        // 토큰 생성
//        String access = jwtUtil.generateToken("access", username, role, 600000L);
//        String refresh = jwtUtil.generateToken("refresh", username, role, 86400000L);
//
//        // 로그인 성공한 유저 정보와 토큰 정보
//        log.info("LoginFilter.successfulAuthentication");
//        log.info("Username : " + username);
//        log.info("role : " + role);
//        log.info("access : " + access);
//        log.info("refresh : " + refresh);
//
//        // Redis에 refresh 토큰 저장
//        redisService.saveRefreshToken(username, refresh);
//
//        // 응답 설정
//        response.setHeader("access", access);
//        response.addCookie(createCookie("refresh", refresh));
//        response.setStatus(HttpStatus.OK.value());
//
////        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();
////        String username = customUserDetails.getUsername();
////
////        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
////        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
////        GrantedAuthority auth = iterator.next();
////        String role = auth.getAuthority();
////
////        String token = jwtUtil.generateToken(username, role);
////
////        response.setHeader("Authorization", "Bearer " + token);
//
//    }
//
//
//    private Cookie createCookie(String key, String value) {
//        Cookie cookie = new Cookie(key, value);
//        cookie.setMaxAge(24 * 60 * 60);
//        cookie.setHttpOnly(true);
//
//        return cookie;
//    }
//
//    @Override
//    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
//                                              AuthenticationException failed) throws IOException, ServletException {
//
//        response.setStatus(401);
//    }
//}
