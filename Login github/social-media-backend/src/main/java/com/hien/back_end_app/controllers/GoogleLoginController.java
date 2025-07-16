package com.hien.back_end_app.controllers;

import com.hien.back_end_app.dto.response.auth.JwtResponseDTO;
import com.hien.back_end_app.services.GoogleLoginService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class GoogleLoginController {

    private final GoogleLoginService googleLoginService;

    @GetMapping("/v1/auth/oauth2/google")
    public JwtResponseDTO handleGoogleLogin(OAuth2AuthenticationToken authentication) {
        return googleLoginService.handleGoogleLogin(authentication);
    }
}
