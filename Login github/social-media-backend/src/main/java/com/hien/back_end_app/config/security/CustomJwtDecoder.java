package com.hien.back_end_app.config.security;

import com.hien.back_end_app.services.JwtService;
import com.hien.back_end_app.utils.enums.TokenType;
import com.nimbusds.jose.JWSAlgorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Objects;

@Component
@RequiredArgsConstructor
public class CustomJwtDecoder implements JwtDecoder {
    @Value("${security.jwt.access.secretKey}")
    private String accessKey;

    private final JwtService jwtService;

    private NimbusJwtDecoder nimbusJwtDecoder;

    @Override
    public Jwt decode(String token) throws JwtException {
        if (nimbusJwtDecoder == null) {
            SecretKey key = new SecretKeySpec(accessKey.getBytes(), JWSAlgorithm.HS256.toString());
            NimbusJwtDecoder nimbusJwtDecoder = NimbusJwtDecoder.withSecretKey(key)
                    .macAlgorithm(MacAlgorithm.HS256)
                    .build();
        }
        jwtService.checkValid(token, TokenType.ACCESS);
        return nimbusJwtDecoder.decode(token);
    }
}
