package com.hien.back_end_app.config.security.securityModels;

import com.hien.back_end_app.entities.Permission;
import com.hien.back_end_app.entities.Role;
import com.hien.back_end_app.entities.User;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

@Setter
@Getter
public class SecurityUser implements OAuth2User {
    private final User user;
    private Map<String, Object> attributes;

    public SecurityUser(User user) {
        this.user = user;
    }

    @Override
    public String getName() {
        return user.getFullName();
    }

    @Override
    public Map<String, Object> getAttributes() {
        return this.attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> result = new ArrayList<>();
        for (Role role : user.getRoles()) {
            result.add(new SecurityAuthority<>(role));
            for (Permission permission : role.getPermissions()) {
                result.add(new SecurityAuthority<>(permission));
            }
        }
        return result;
    }
}
