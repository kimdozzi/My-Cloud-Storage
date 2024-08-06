package com.example.deploy.security.jwt.util;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;
import lombok.Getter;
import org.springframework.stereotype.Component;

@Component
@Getter
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
                .setExpiration(new Date(System.currentTimeMillis() + expiredMs)) // 10시간 유효

                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
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
