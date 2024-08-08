package com.example.deploy.user.controller;

import static com.example.deploy.global.util.SuccessCode.JOIN_SUCCESS;

import com.example.deploy.global.response.SingleResponse;
import com.example.deploy.global.util.SuccessCode;
import com.example.deploy.user.dto.JoinRequest;
import com.example.deploy.user.dto.JoinResponse;
import com.example.deploy.user.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    private final UserService userService;

    public AuthController(UserService userService) {
        this.userService = userService;
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
}