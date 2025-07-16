package com.hien.back_end_app.config.security.oauth2.models;

import com.hien.back_end_app.utils.enums.AuthProvider;
import lombok.Getter;
import lombok.Setter;

import java.util.Map;


@Getter
@Setter
public abstract class OAuth2UserInfo {
    protected Map<String, Object> attributes;

    public OAuth2UserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    public Map<String, Object> getAttributes() {
        return attributes;
    }

    public abstract String getId();

    public abstract String getName();

    public abstract String getEmail();

    public abstract String getImageUrl();

   public static OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
    if (registrationId.equalsIgnoreCase(AuthProvider.GOOGLE.name())) {
        return new GoogleOAuth2UserInfo(attributes);
    } else if (registrationId.equalsIgnoreCase(AuthProvider.FACEBOOK.name())) {
        return new FacebookOAuth2UserInfo(attributes);
    } else if (registrationId.equalsIgnoreCase(AuthProvider.GITHUB.name())) {
        return new GithubOAuth2UserInfo(attributes); // 👈 Bổ sung dòng này
    }
    return null;
}
}
