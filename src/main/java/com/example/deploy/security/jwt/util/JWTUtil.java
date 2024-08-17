package com.example.deploy.security.jwt.util;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Component
@Getter
@Slf4j
public class JWTUtil {
    private static final Key key = Keys.secretKeyFor(SignatureAlgorithm.HS512);

    // JWT 토큰 검증 및 클레임 파싱
    public static Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key) // 서명 키 설정
                .build()
                .parseClaimsJws(token) // 토큰 파싱 및 검증
                .getBody(); // 클레임 반환
    }

    // JWT 토큰 생성
    public String generateToken(String category, String username, String role, Long expiredMs) {

        return Jwts.builder()

                // username
                .setSubject(username)

                // category
                .claim("category", category)

                // role
                .claim("role", role)

                // 생성일
                .setIssuedAt(new Date(System.currentTimeMillis()))

                // 만료일
                .setExpiration(new Date(System.currentTimeMillis() + expiredMs))

                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }

    public void validateToken(String token) {
        try {
            getClaims(token);
        } catch (io.jsonwebtoken.security.SignatureException ex) {
            // 서명이 유효하지 않은 경우
            log.error("Invalid JWT signature: {}", ex.getMessage());

        } catch (io.jsonwebtoken.ExpiredJwtException ex) {
            // 토큰이 만료된 경우
            log.error("Expired JWT token: {}", ex.getMessage());

        } catch (io.jsonwebtoken.MalformedJwtException ex) {
            // 토큰이 잘못된 형식일 경우
            log.error("Invalid JWT token: {}", ex.getMessage());

        } catch (io.jsonwebtoken.UnsupportedJwtException ex) {
            // 지원되지 않는 JWT 토큰일 경우
            log.error("Unsupported JWT token: {}", ex.getMessage());

        } catch (IllegalArgumentException ex) {
            // 빈 토큰이 제공된 경우
            log.error("JWT claims string is empty: {}", ex.getMessage());

        } catch (JwtException ex) {
            // 그 외의 JWT 관련 예외가 발생한 경우
            log.error("JWT validation error: {}", ex.getMessage());
        }
    }

    public String getCategory(String token) {
        return getClaims(token).get("category", String.class);
    }

    // 토큰에서 username 추출
    public String getUsername(String token) {
        return getClaims(token).getSubject();
    }

    // 토큰에서 role 추출
    public String getRole(String token) {
        return getClaims(token).get("role", String.class);
    }

    // 토큰 만료 여부 확인
    public boolean isTokenExpired(String token) {
        return getClaims(token).getExpiration().before(new Date());
    }
}
