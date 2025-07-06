package com.hien.back_end_app.exceptions;

import com.hien.back_end_app.utils.enums.ErrorCode;
import lombok.Getter;


@Getter
public class AppException extends RuntimeException {
    private final ErrorCode errorCode;

    public AppException(ErrorCode errorCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
    }
}
