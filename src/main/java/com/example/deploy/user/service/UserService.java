package com.example.deploy.user.service;

import com.example.deploy.user.domain.User;
import com.example.deploy.user.dto.JoinRequest;
import com.example.deploy.user.dto.JoinResponse;
import com.example.deploy.user.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Transactional
@Service
public class UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public UserService(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    public JoinResponse createUser(JoinRequest joinRequest) {
        String username = joinRequest.username();
        String password = joinRequest.password();

        Boolean isExist = userRepository.existsByUsername(username);

        if (isExist) {
            return null;
        }

        User user = new User();
        user.setUsername(username);
        user.setPassword(bCryptPasswordEncoder.encode(password));
        user.setRole("ROLE_ADMIN");

        userRepository.save(user);

        return JoinResponse.builder().username(user.getUsername()).role(user.getRole()).build();
    }
}
