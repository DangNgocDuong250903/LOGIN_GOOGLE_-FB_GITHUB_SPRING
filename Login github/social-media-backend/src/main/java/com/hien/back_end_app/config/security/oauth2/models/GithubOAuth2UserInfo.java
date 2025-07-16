package com.hien.back_end_app.config.security.oauth2.models;

import java.util.Map;

public class GithubOAuth2UserInfo extends OAuth2UserInfo {
    public GithubOAuth2UserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getId() {
        return String.valueOf(attributes.get("id"));
    }

    @Override
    public String getName() {
        return (String) attributes.get("name");
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email"); // sẽ được set lại từ extractEmail()
    }

    @Override
    public String getImageUrl() {
        return (String) attributes.get("avatar_url");
    }
}
