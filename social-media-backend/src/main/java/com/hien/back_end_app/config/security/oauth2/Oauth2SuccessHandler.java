package com.hien.back_end_app.config.security.oauth2;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hien.back_end_app.config.security.securityModels.SecurityUser;
import com.hien.back_end_app.dto.response.auth.JwtResponseDTO;
import com.hien.back_end_app.services.JwtService;
import com.hien.back_end_app.utils.enums.TokenType;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;


@Component
@RequiredArgsConstructor
public class Oauth2SuccessHandler implements AuthenticationSuccessHandler {
    private final JwtService jwtService;

//    @Override
//    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//        SecurityUser user = (SecurityUser) authentication.getPrincipal();
//        // call tokenService to generate token from user
//        String accessToken = jwtService.generateToken(user.getUser(), TokenType.ACCESS);
//        String refreshToken = jwtService.generateToken(user.getUser(), TokenType.REFRESH);
//        JwtResponseDTO tokenResponse = JwtResponseDTO.builder()
//                .accessToken(accessToken)
//                .refreshToken(refreshToken)
//                .build();
//        response.setContentType("application/json");
//        new ObjectMapper().writeValue(response.getWriter(), tokenResponse);
//    }
    @Override
public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                     Authentication authentication) throws IOException {
    SecurityUser user = (SecurityUser) authentication.getPrincipal();

    String accessToken = jwtService.generateToken(user.getUser(), TokenType.ACCESS);
    String refreshToken = jwtService.generateToken(user.getUser(), TokenType.REFRESH);

    String redirectUrl = "http://localhost:3000/oauth2/success"
            + "?accessToken=" + accessToken
            + "&refreshToken=" + refreshToken;

    response.sendRedirect(redirectUrl);
}
}
