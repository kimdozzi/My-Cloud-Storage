package com.example.deploy.security.jwt;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;
import org.springframework.stereotype.Component;

@Component
public class JWTUtil {
    private static final Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    public static Key getKey() {
        return key;
    }

    // JWT 토큰 생성
    public String generateToken(String username, String role) {
        return Jwts.builder()
                // username
                .setSubject(username)

                // role
                .claim("role", role)

                // 생성일
                .setIssuedAt(new Date(System.currentTimeMillis()))

                // 만료일
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10)) // 10시간 유효

                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    // JWT 토큰 검증 및 파싱
    public Claims validateToken(String token) {
        Jws<Claims> claimsJws = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token);

        return claimsJws.getBody();
    }
}
