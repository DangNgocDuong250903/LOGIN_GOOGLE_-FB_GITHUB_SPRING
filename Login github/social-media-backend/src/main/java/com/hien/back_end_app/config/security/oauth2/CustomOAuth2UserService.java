package com.hien.back_end_app.config.security.oauth2;


import com.hien.back_end_app.config.security.oauth2.models.OAuth2UserInfo;
import com.hien.back_end_app.config.security.securityModels.SecurityUser;
import com.hien.back_end_app.entities.User;
import com.hien.back_end_app.exceptions.AppException;
import com.hien.back_end_app.repositories.UserRepository;
import com.hien.back_end_app.utils.enums.AuthProvider;
import com.hien.back_end_app.utils.enums.ErrorCode;
import io.micrometer.common.util.StringUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.util.*;


@Component
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepository;

    //    @Override
//    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
//        OAuth2User oAuth2User = super.loadUser(userRequest);
//        return checkingUser(userRequest, oAuth2User);
//    }
    private String getEmailFromGithub(OAuth2UserRequest userRequest) {
        String token = userRequest.getAccessToken().getTokenValue();
        RestTemplate restTemplate = new RestTemplate();

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "token " + token);
        headers.add("Accept", "application/vnd.github.v3+json");

        HttpEntity<Void> entity = new HttpEntity<>(headers);
        ResponseEntity<List<Map<String, Object>>> response = restTemplate.exchange(
                "https://api.github.com/user/emails",
                HttpMethod.GET,
                entity,
                new ParameterizedTypeReference<>() {
                }
        );

        return response.getBody().stream()
                .filter(email -> Boolean.TRUE.equals(email.get("primary")) && Boolean.TRUE.equals(email.get("verified")))
                .map(email -> (String) email.get("email"))
                .findFirst()
                .orElse(null);
    }

    private String getPrimaryEmailFromGithub(OAuth2UserRequest userRequest) {
        try {
            String token = userRequest.getAccessToken().getTokenValue();
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);
            headers.setAccept(List.of(MediaType.APPLICATION_JSON));

            HttpEntity<Void> entity = new HttpEntity<>(headers);

            ResponseEntity<List> response = new RestTemplate().exchange(
                    "https://api.github.com/user/emails",
                    HttpMethod.GET,
                    entity,
                    List.class
            );

            List<Map<String, Object>> emails = response.getBody();
            if (emails != null) {
                for (Map<String, Object> emailObj : emails) {
                    if (Boolean.TRUE.equals(emailObj.get("primary")) && Boolean.TRUE.equals(emailObj.get("verified"))) {
                        return (String) emailObj.get("email");
                    }
                }
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        Map<String, Object> attributes = new HashMap<>(oAuth2User.getAttributes());

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        String email = (String) attributes.get("email");

        // 🔍 Nếu là GitHub mà email null thì xử lý bổ sung
        if ("github".equals(registrationId) && email == null) {
            email = getPrimaryEmailFromGithub(userRequest);
            if (email == null && attributes.containsKey("login")) {
                email = attributes.get("login") + "@github.com"; // fallback nếu GitHub vẫn không trả
            }
    }

        if (email == null) {
            throw new AppException(ErrorCode.EMAIL_NULL);
        }

        attributes.put("email", email);

        return checkingUser(userRequest, new DefaultOAuth2User(
                oAuth2User.getAuthorities(),
                attributes,
                "email"
        ));
    }

    private OAuth2User checkingUser(OAuth2UserRequest userRequest, OAuth2User oAuth2User) {
        OAuth2UserInfo userInfo = OAuth2UserInfo.getOAuth2UserInfo(userRequest.getClientRegistration().getRegistrationId(),
                oAuth2User.getAttributes());
        if (userInfo == null || StringUtils.isEmpty(userInfo.getEmail())) {
            throw new AppException(ErrorCode.OAuth2CheckingException);
        }
        Optional<User> userOptional = userRepository.findByEmail(userInfo.getEmail());
        User user;
        if (userOptional.isPresent()) {
            // if user present , check if the registration right?, update the name and the image
            // from the third-account
            user = userOptional.get();
            if (!user.getAuthProvider().name().equalsIgnoreCase(userRequest.getClientRegistration().getRegistrationId())) {
                throw new AppException(ErrorCode.OAuth2InvalidProvider);
            }
            user = updateExistingUser(user, userInfo);
        } else {
            // if cant find user, create new user with the information from third-account
            user = registerNewUser(userRequest, userInfo);
        }

        // convert to userDetail
        SecurityUser returnUser = new SecurityUser(user);
        returnUser.setAttributes(userInfo.getAttributes());
        return returnUser;
    }

    private User updateExistingUser(User oldUser, OAuth2UserInfo userInfo) {
        oldUser.setFullName(userInfo.getName());
        oldUser.setImageUrl(userInfo.getImageUrl());
        userRepository.save(oldUser);
        return oldUser;
    }

    private User registerNewUser(OAuth2UserRequest userRequest, OAuth2UserInfo userInfo) {
        User user = new User();
        user.setAuthProvider(AuthProvider.from(userRequest.getClientRegistration().getRegistrationId()));
        user.setProviderId(userInfo.getId());
        user.setFullName(userInfo.getName());
        user.setEmail(userInfo.getEmail());
        user.setImageUrl(userInfo.getImageUrl());

        user.setRoles(new HashSet<>());

        return userRepository.save(user);
    }

    private String extractEmail(OAuth2UserRequest userRequest, OAuth2User oAuth2User) {
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        Map<String, Object> attributes = oAuth2User.getAttributes();
        String email = (String) attributes.get("email");

        if ("github".equals(registrationId) && email == null) {
            try {
                String token = userRequest.getAccessToken().getTokenValue();
                HttpHeaders headers = new HttpHeaders();
                headers.setBearerAuth(token);
                headers.setAccept(List.of(MediaType.APPLICATION_JSON));
                HttpEntity<Void> entity = new HttpEntity<>(headers);

                ResponseEntity<List> response = new RestTemplate().exchange(
                        "https://api.github.com/user/emails",
                        HttpMethod.GET,
                        entity,
                        List.class
                );

                List<Map<String, Object>> emails = response.getBody();
                if (emails != null) {
                    for (Map<String, Object> e : emails) {
                        Boolean primary = (Boolean) e.get("primary");
                        Boolean verified = (Boolean) e.get("verified");
                        if (Boolean.TRUE.equals(primary) && Boolean.TRUE.equals(verified)) {
                            email = (String) e.get("email");
                            break;
                        }
                    }
                }
            } catch (Exception ex) {
                ex.printStackTrace(); // log nếu cần
            }
        }

        // 👉 Nếu vẫn null thì tạo email giả từ login name
        if (email == null && "github".equals(registrationId)) {
            Object login = attributes.get("login"); // login name của GitHub user
            if (login != null) {
                email = login + "@github.com";
            }
        }

        return email;
    }

}
