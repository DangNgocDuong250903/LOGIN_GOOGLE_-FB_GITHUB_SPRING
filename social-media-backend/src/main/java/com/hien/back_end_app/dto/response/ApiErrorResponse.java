package com.hien.back_end_app.dto.response;

import lombok.Getter;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

import java.io.Serializable;

@Setter
@Getter
@SuperBuilder
public class ApiErrorResponse extends ApiResponse implements Serializable {
    private String error;
    private String path;
}
