package com.hien.back_end_app.config.security.oauth2;


import com.hien.back_end_app.config.security.securityModels.SecurityUser;
import com.hien.back_end_app.entities.User;
import com.hien.back_end_app.exceptions.AppException;
import com.hien.back_end_app.config.security.oauth2.models.OAuth2UserInfo;
import com.hien.back_end_app.repositories.UserRepository;
import com.hien.back_end_app.utils.enums.AuthProvider;
import com.hien.back_end_app.utils.enums.ErrorCode;
import io.micrometer.common.util.StringUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;


import java.util.HashSet;
import java.util.Optional;


@Component
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        return checkingUser(userRequest, oAuth2User);
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
}
