package com.example.deploy.user.controller;

import com.example.deploy.user.dto.JoinDTO;
import com.example.deploy.user.service.UserService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody
public class MainController {

    private final UserService userService;

    public MainController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/")
    public String mainP() {

        return "main Controller";
    }

    @GetMapping("/admin")
    @PreAuthorize("isAuthenticated() and hasRole('ROLE_ADMIN')")
    public String adminP() {

        return "admin Controller";
    }

    @PostMapping("/join")
    public String joinProcess(JoinDTO joinDTO) {

        userService.joinProcess(joinDTO);
        return "Ok";
    }
}