package com.hien.back_end_app.dto.response;


import lombok.Getter;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

import java.io.Serializable;

@SuperBuilder
@Setter
@Getter
public abstract class ApiResponse implements Serializable {
    protected int status;
    protected String message;
}
