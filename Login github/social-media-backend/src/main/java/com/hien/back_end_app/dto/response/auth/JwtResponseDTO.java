package com.hien.back_end_app.dto.response.auth;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@Setter
@Getter
@Builder
public class JwtResponseDTO implements Serializable {
    private String accessToken;
    private String refreshToken;
}
