package com.example.deploy.redis.service;

import java.util.concurrent.TimeUnit;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

@Service
public class RedisService {
    private static final String PREFIX_REFRESH_TOKEN = "refresh:";
    private final RedisTemplate<String, Object> redisTemplate;

    public RedisService(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void saveRefreshToken(String username, String refreshToken, long ttl) {
        redisTemplate.opsForValue().set(PREFIX_REFRESH_TOKEN + username, refreshToken, ttl, TimeUnit.DAYS);
    }

    public String getRefreshToken(String username) {
        return (String) redisTemplate.opsForValue().get(PREFIX_REFRESH_TOKEN + username);
    }

    public void deleteRefreshToken(String username) {
        redisTemplate.delete(PREFIX_REFRESH_TOKEN + username);
    }
}