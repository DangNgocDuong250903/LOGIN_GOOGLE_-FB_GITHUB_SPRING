package com.hien.back_end_app.config.security.securityModels;

import com.hien.back_end_app.entities.Permission;
import com.hien.back_end_app.entities.Role;
import com.hien.back_end_app.exceptions.AppException;
import com.hien.back_end_app.utils.enums.ErrorCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;


@RequiredArgsConstructor
@Slf4j
public class SecurityAuthority<T> implements GrantedAuthority {
    private final T authority;

    @Override
    public String getAuthority() {
        if (authority instanceof Role) {
            return "ROLE_" + ((Role) authority).getName();
        } else if (authority instanceof Permission) {
            return ((Permission) authority).getName();
        }
        throw new AppException(ErrorCode.AUTHORITY_TYPE_INVALID);
    }
}