package com.example.deploy.security.oauth2.service;

import com.example.deploy.security.oauth2.dto.CustomOAuth2User;
import com.example.deploy.security.oauth2.dto.GoogleOAuth2Response;
import com.example.deploy.security.oauth2.dto.NaverOAuth2Response;
import com.example.deploy.security.oauth2.dto.OAuth2Response;
import com.example.deploy.security.oauth2.dto.UserDTO;
import com.example.deploy.user.domain.User;
import com.example.deploy.user.repository.UserRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    public CustomOAuth2UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println(oAuth2User);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        OAuth2Response oAuth2Response;
        if (registrationId.equals("naver")) {
            oAuth2Response = new NaverOAuth2Response(oAuth2User.getAttributes());
        } else if(registrationId.equals("google")) {
            oAuth2Response = new GoogleOAuth2Response(oAuth2User.getAttributes());
        } else return null;


        //리소스 서버에서 발급 받은 정보로 사용자를 특정할 아이디값을 만듬
        String username = oAuth2Response.getProvider()+" "+oAuth2Response.getProviderId();

        User existData = userRepository.findByUsername(username);
        if (existData == null) {
            User user = User.builder()
                    .username(username)
                    .email(oAuth2Response.getEmail())
                    .name(oAuth2Response.getName())
                    .role("ROLE_USER")
                    .build();

            userRepository.save(user);

            UserDTO userDTO = UserDTO.builder()
                    .username(username)
                    .name(oAuth2Response.getName())
                    .email(oAuth2Response.getEmail())
                    .role("ROLE_USER")
                    .build();

            return new CustomOAuth2User(userDTO);

        } else {
            existData.setEmail(oAuth2Response.getEmail());
            existData.setName(oAuth2Response.getName());

            userRepository.save(existData);

            UserDTO userDTO = UserDTO.builder()
                    .username(existData.getUsername())
                    .name(oAuth2Response.getName())
                    .email(oAuth2Response.getEmail())
                    .role("ROLE_USER")
                    .build();

            return new CustomOAuth2User(userDTO);
        }
//
//        UserDTO userDTO = UserDTO.builder()
//                .role("ROLE_USER")
//                .name(oAuth2Response.getName())
//                .username(username)
//                .build();

//        return new CustomOAuth2User(userDTO);
    }
}
