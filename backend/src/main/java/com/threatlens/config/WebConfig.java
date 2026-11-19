package com.threatlens.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.io.IOException;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    private final ThreatLensProperties props;

    public WebConfig(ThreatLensProperties props) {
        this.props = props;
    }

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
                .allowedOrigins(props.corsOrigins().toArray(String[]::new))
                .allowedMethods("GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS");
    }

    /** Optional shared-secret protection for ingestion endpoints (log shippers, scripts). */
    @Bean
    FilterRegistrationBean<OncePerRequestFilter> ingestApiKeyFilter() {
        OncePerRequestFilter filter = new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
                    throws ServletException, IOException {
                String expected = props.ingestApiKey();
                if (expected != null && !expected.isBlank() && "POST".equals(req.getMethod())) {
                    String given = req.getHeader("X-API-Key");
                    boolean ok = given != null && MessageDigest.isEqual(
                            expected.getBytes(StandardCharsets.UTF_8), given.getBytes(StandardCharsets.UTF_8));
                    if (!ok) {
                        res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Missing or invalid X-API-Key");
                        return;
                    }
                }
                chain.doFilter(req, res);
            }
        };
        FilterRegistrationBean<OncePerRequestFilter> reg = new FilterRegistrationBean<>(filter);
        reg.addUrlPatterns("/api/ingest/*");
        return reg;
    }
}
