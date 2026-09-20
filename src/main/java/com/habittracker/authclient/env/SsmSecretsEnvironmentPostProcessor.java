package com.habittracker.authclient.env;

import java.io.IOException;
import java.io.StringReader;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.function.Function;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.GetParameterRequest;

public class SsmSecretsEnvironmentPostProcessor implements EnvironmentPostProcessor {
    private static final String SOURCE_ENV_VAR = "SSM_BACKED_PROPERTIES";
    private static final String PROPERTY_SOURCE_NAME = "ssmBackedSecrets";
    private static final String REGION_PROPERTY = "aws.region";

    private final Function<Region, SsmClient> clientFactory;

    public SsmSecretsEnvironmentPostProcessor() {
        this(region -> SsmClient.builder().region(region).build());
    }

    SsmSecretsEnvironmentPostProcessor(Function<Region, SsmClient> clientFactory) {
        this.clientFactory = clientFactory;
    }

    @Override
    public void postProcessEnvironment(
            ConfigurableEnvironment environment, SpringApplication application) {
        String encoded = environment.getProperty(SOURCE_ENV_VAR);
        if (encoded == null || encoded.isBlank()) {
            return;
        }

        Region region = Region.of(environment.getRequiredProperty(REGION_PROPERTY));
        Map<String, Object> resolved;
        try (SsmClient ssmClient = clientFactory.apply(region)) {
            resolved = resolveAll(parsePropertyPaths(encoded), ssmClient);
        }
        environment
                .getPropertySources()
                .addFirst(new MapPropertySource(PROPERTY_SOURCE_NAME, resolved));
    }

    static Properties parsePropertyPaths(String encoded) {
        Properties propertyPaths = new Properties();
        try (StringReader reader = new StringReader(encoded)) {
            propertyPaths.load(reader);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to parse " + SOURCE_ENV_VAR, e);
        }
        return propertyPaths;
    }

    static Map<String, Object> resolveAll(Properties propertyPaths, SsmClient ssmClient) {
        Map<String, Object> resolved = new LinkedHashMap<>();
        for (String propertyName : propertyPaths.stringPropertyNames()) {
            String path = propertyPaths.getProperty(propertyName);
            String value =
                    ssmClient
                            .getParameter(
                                    GetParameterRequest.builder()
                                            .name(path)
                                            .withDecryption(true)
                                            .build())
                            .parameter()
                            .value();
            resolved.put(propertyName, value);
        }
        return resolved;
    }
}
