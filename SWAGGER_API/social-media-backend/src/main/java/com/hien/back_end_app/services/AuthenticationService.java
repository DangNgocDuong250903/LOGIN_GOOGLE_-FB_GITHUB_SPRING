package com.hien.back_end_app.services;


import com.hien.back_end_app.dto.request.LoginStandardRequestDTO;
import com.hien.back_end_app.dto.response.auth.JwtResponseDTO;
import com.hien.back_end_app.entities.User;
import com.hien.back_end_app.exceptions.AppException;
import com.hien.back_end_app.repositories.UserRepository;

import com.hien.back_end_app.utils.enums.AuthProvider;
import com.hien.back_end_app.utils.enums.ErrorCode;
import com.hien.back_end_app.utils.enums.TokenType;
import com.hien.back_end_app.utils.enums.UserStatus;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    public JwtResponseDTO login(LoginStandardRequestDTO dto) {
        String email = dto.getEmail();
        String password = dto.getPassword();

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new AppException(ErrorCode.USER_NOT_EXISTED));
        String userPassword = user.getPassword();
        if (!passwordEncoder.matches(password, userPassword)) {
            throw new AppException(ErrorCode.UNAUTHORIZED);
        }

        // gen token
        String accessToken = jwtService.generateToken(user, TokenType.ACCESS);
        String refreshToken = jwtService.generateToken(user, TokenType.REFRESH);

        // save refresh token in persistent db
        // save access token in redis

        return JwtResponseDTO.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }
public JwtResponseDTO loginWithGoogleUser(String email, String fullName, String googleId, String avatarUrl) {
    User user = userRepository.findByEmail(email).orElseGet(() -> {
        User newUser = User.builder()
                .email(email)
                .fullName(fullName)
                .password("") // không cần mật khẩu
                .authProvider(AuthProvider.GOOGLE)
                .providerId(googleId)
                .imageUrl(avatarUrl)
                .userStatus(UserStatus.ACTIVE) // nên có trạng thái mặc định
                .build();
        return userRepository.save(newUser);
    });

    // Nếu user đã tồn tại nhưng thiếu thông tin
    boolean updated = false;

    if (user.getAuthProvider() == null) {
        user.setAuthProvider(AuthProvider.GOOGLE);
        updated = true;
    }

    if (user.getProviderId() == null) {
        user.setProviderId(googleId);
        updated = true;
    }

    if (user.getImageUrl() == null && avatarUrl != null) {
        user.setImageUrl(avatarUrl);
        updated = true;
    }

    if (updated) {
        userRepository.save(user);
    }

    String accessToken = jwtService.generateToken(user, TokenType.ACCESS);
    String refreshToken = jwtService.generateToken(user, TokenType.REFRESH);

    return JwtResponseDTO.builder()
            .accessToken(accessToken)
            .refreshToken(refreshToken)
            .build();
}


}
