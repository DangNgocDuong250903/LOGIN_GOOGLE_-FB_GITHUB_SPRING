package com.hien.back_end_app.services;

import com.hien.back_end_app.entities.Permission;
import com.hien.back_end_app.entities.Role;
import com.hien.back_end_app.entities.User;
import com.hien.back_end_app.exceptions.AppException;
import com.hien.back_end_app.utils.enums.ErrorCode;
import com.hien.back_end_app.utils.enums.TokenType;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.text.ParseException;
import java.util.Date;
import java.util.StringJoiner;
import java.util.UUID;
import java.util.function.Function;


@Service
@Slf4j
public class JwtService {
    @Value("${security.jwt.access.timeout}")
    private long accessTTL;
    @Value("${security.jwt.refresh.timeout}")
    private long refreshTTL;
    @Value("${security.jwt.reset.timeout}")
    private long resetTTL;

    @Value("${security.jwt.access.secretKey}")
    private String accessKey;
    @Value("${security.jwt.refresh.secretKey}")
    private String refreshKey;
    @Value("${security.jwt.reset.secretKey}")
    private String resetKey;

    public String generateToken(User user, TokenType type) {
        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        long ttl = 0;
        String secretKey;
        if (type.equals(TokenType.ACCESS)) {
            ttl = accessTTL * 60 * 1000L;
            secretKey = accessKey;
        } else if (type.equals(TokenType.REFRESH)) {
            ttl = refreshTTL * 30 * 24 * 60 * 60 * 1000L;
            secretKey = refreshKey;
        } else {
            ttl = resetTTL * 60 * 1000L;
            secretKey = resetKey;
        }
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(user.getEmail())
                .issuer("social-network-app")
                .issueTime(new Date(System.currentTimeMillis()))
                .expirationTime(new Date(System.currentTimeMillis() + ttl))
                .jwtID(UUID.randomUUID().toString())
                .claim("scope", buildScope(user))
                .build();

        Payload payload = new Payload(claimsSet.toJSONObject());

        JWSObject jwsObject = new JWSObject(header, payload);

        try {
            jwsObject.sign(new MACSigner(secretKey));
        } catch (JOSEException e) {
            log.error(ErrorCode.JWT_SIGN_ERROR.name(), e);
            throw new AppException(ErrorCode.JWT_SIGN_ERROR);
        }
        return jwsObject.serialize();
    }


    public void checkValid(String token, TokenType type) {
        try {
            // check signature
            SignedJWT signedJWT = SignedJWT.parse(token);
            String secretKey = getSecretKey(type);
            JWSVerifier verifier = new MACVerifier(secretKey);
            if (!signedJWT.verify(verifier)) {
                throw new AppException(ErrorCode.TOKEN_SIGNATURE_INVALID);
            }
            // check expiration
            Date expiration = extractExpiration(token);
            if (expiration == null || new Date().after(expiration)) {
                throw new AppException(ErrorCode.TOKEN_EXPIRED);
            }
            // check disable or token black list
        } catch (ParseException e) {
            throw new AppException(ErrorCode.TOKEN_INVALID);
        } catch (JOSEException e) {
            throw new AppException(ErrorCode.TOKEN_SIGNATURE_INVALID);
        }
    }


    public Date extractExpiration(String token) {
        return extractFieldFromPayload(token, JWTClaimsSet::getExpirationTime);
    }

    public String extractUsername(String token) {
        return extractFieldFromPayload(token, JWTClaimsSet::getSubject);
    }

    private String getSecretKey(TokenType type) {
        return switch (type) {
            case ACCESS -> accessKey;
            case REFRESH -> refreshKey;
            case RESET -> resetKey;
            default -> throw new AppException(ErrorCode.TOKEN_INVALID);
        };
    }


    private <T> T extractFieldFromPayload(String token, Function<JWTClaimsSet, T> function) {
        return function.apply(getClaimSets(token));
    }

    private JWTClaimsSet getClaimSets(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            return signedJWT.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    private String buildScope(User user) {
        StringJoiner stringJoiner = new StringJoiner(" ");
        if (!CollectionUtils.isEmpty(user.getRoles()))
            user.getRoles().forEach(role -> {
                stringJoiner.add("ROLE_" + role.getName());
                if (!CollectionUtils.isEmpty(role.getPermissions()))
                    role.getPermissions().forEach(permission -> stringJoiner.add(permission.getName()));
            });
        return stringJoiner.toString();
    }
}
