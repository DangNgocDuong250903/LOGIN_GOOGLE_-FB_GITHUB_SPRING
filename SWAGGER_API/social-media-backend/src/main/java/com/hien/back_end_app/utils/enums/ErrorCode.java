package com.hien.back_end_app.utils.enums;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.boot.autoconfigure.graphql.GraphQlProperties;
import org.springframework.http.HttpStatus;


@AllArgsConstructor
@Getter
public enum ErrorCode {
    OAuth2CheckingException(400, "oauth2 user is null or can't get email from oauth2 user", HttpStatus.BAD_REQUEST),
    OAuth2InvalidProvider(400, "seem that your email is linked with other auth provider, check again", HttpStatus.BAD_REQUEST),
    JWT_SIGN_ERROR(500, "seem that server can't handle sign jwt", HttpStatus.INTERNAL_SERVER_ERROR),
    TOKEN_INVALID(400, "given token is invalid,try to login again to call to refresh token", HttpStatus.BAD_REQUEST),
    TOKEN_SIGNATURE_INVALID(400, "given token signature is invalid", HttpStatus.BAD_REQUEST),
    TOKEN_DISABLED(400, "given token is disable by logged out", HttpStatus.BAD_REQUEST),
    TOKEN_EXPIRED(400, "given token is expired", HttpStatus.BAD_REQUEST),
    USER_NOT_EXISTED(400, "can't find any user with given email", HttpStatus.BAD_REQUEST),
    UNAUTHORIZED(401, "user unathorized", HttpStatus.UNAUTHORIZED),
    ACCESS_DENIED(403, "you dont have permission to do this", HttpStatus.FORBIDDEN),
    AUTHORITY_TYPE_INVALID(400, "authority type is invalid, try again", HttpStatus.BAD_REQUEST);
    private final int code;
    private final String message;
    private final HttpStatus httpStatus;
}
