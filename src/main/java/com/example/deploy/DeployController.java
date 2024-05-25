package com.example.deploy;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class DeployController {
    @GetMapping("/")
    public ResponseEntity hello() {
        return ResponseEntity.ok("배포 자동화 테스트");
    }
}
