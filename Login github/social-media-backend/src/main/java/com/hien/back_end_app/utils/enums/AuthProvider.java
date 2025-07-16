package com.hien.back_end_app.utils.enums;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.openid.connect.sdk.claims.Gender;

public enum AuthProvider {

    @JsonProperty("standard")
    STANDARD,
    @JsonProperty("google")
    GOOGLE,
    @JsonProperty("facebook")
    FACEBOOK,
    @JsonProperty("github")
    GITHUB,

    UNKNOWN;;

    @JsonCreator
    public static AuthProvider from(String value) {
        if (value == null) return UNKNOWN;
        try {
            return AuthProvider.valueOf(value.toUpperCase());
        } catch (IllegalArgumentException e) {
            return UNKNOWN;
        }
    }
}
