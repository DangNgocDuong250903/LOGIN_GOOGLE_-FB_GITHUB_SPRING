package com.hien.back_end_app.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.parser.OpenAPIV3Parser;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.beans.factory.annotation.Value;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI customOpenAPI(@Value("classpath:duytnuniversity-social-network-api-1.0.0-resolved.yaml") Resource apiSpec) throws IOException {
        String openApiContent = new String(apiSpec.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        return new OpenAPIV3Parser().readContents(openApiContent, null, null).getOpenAPI();
    }
}
