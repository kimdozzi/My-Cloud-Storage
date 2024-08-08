package com.example.deploy.global.util;


import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {

    MEMBER_NOT_UPDATED(HttpStatus.BAD_REQUEST, "유저 정보가 업데이트되지 않았습니다."),
    INVALID_PASSWORD(HttpStatus.BAD_REQUEST, "유저 비밀번호가 일치하지 않았습니다."),

    ALREADY_REGISTERED(HttpStatus.BAD_REQUEST, "이미 회원가입이 완료된 사용자입니다."),
    MEMBER_NOT_FOUND(HttpStatus.NOT_FOUND, "회원 정보를 찾을 수 없습니다."),
    DUPLICATED_NICKNAME(HttpStatus.BAD_REQUEST, "이미 존재하는 닉네임입니다."),
    NOT_AUTHENTICATED_USER(HttpStatus.BAD_REQUEST, "인증 가능한 사용자가 아닙니다."),

    INVALID_EXPIRED_JWT(HttpStatus.BAD_REQUEST, "이미 만료된 JWT 입니다."),
    INVALID_MALFORMED_JWT(HttpStatus.BAD_REQUEST, "JWT의 구조가 유효하지 않습니다."),
    INVALID_CLAIM_JWT(HttpStatus.BAD_REQUEST, "JWT의 Claim이 유효하지 않습니다."),
    UNSUPPORTED_JWT(HttpStatus.BAD_REQUEST, "지원하지 않는 JWT 형식입니다."),
    INVALID_JWT(HttpStatus.BAD_REQUEST, "JWT가 유효하지 않습니다."),
    INVALID_PROGRESS(HttpStatus.BAD_REQUEST, "존재하지 않는 정보입니다.");


    private final HttpStatus status;
    private final String message;
}
