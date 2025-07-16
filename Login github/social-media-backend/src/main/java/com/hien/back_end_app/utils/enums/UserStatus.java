package com.hien.back_end_app.utils.enums;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public enum UserStatus {
    @JsonProperty("active")
    ACTIVE,
    @JsonProperty("online")
    ONLINE,
    @JsonProperty("offline")
    OFFLINE,

    UNKNOWN;

    @JsonCreator
    public static UserStatus from(String value) {
        if (value == null) return UNKNOWN;
        try {
            return UserStatus.valueOf(value.toUpperCase());
        } catch (IllegalArgumentException e) {
            return UNKNOWN;
        }
    }
}
