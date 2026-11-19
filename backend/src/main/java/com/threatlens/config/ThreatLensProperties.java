package com.threatlens.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@ConfigurationProperties(prefix = "threatlens")
public record ThreatLensProperties(
        String mlServiceUrl,
        String ingestApiKey,
        List<String> corsOrigins,
        List<String> criticalAssets) {

    public ThreatLensProperties {
        corsOrigins = corsOrigins == null ? List.of() : corsOrigins;
        criticalAssets = criticalAssets == null ? List.of() : criticalAssets;
    }
}
