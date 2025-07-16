package com.hien.back_end_app.services;

import com.hien.back_end_app.dto.response.auth.JwtResponseDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class GoogleLoginService {
    private final AuthenticationService authenticationService;

    public JwtResponseDTO handleGoogleLogin(OAuth2AuthenticationToken authentication) {
        String email = authentication.getPrincipal().getAttribute("email");
        String name = authentication.getPrincipal().getAttribute("name");
        String sub = authentication.getPrincipal().getAttribute("sub"); // googleId
        String picture = authentication.getPrincipal().getAttribute("picture"); // picture URL

        return authenticationService.loginWithGoogleUser(email, name, sub,picture);
    }
}
