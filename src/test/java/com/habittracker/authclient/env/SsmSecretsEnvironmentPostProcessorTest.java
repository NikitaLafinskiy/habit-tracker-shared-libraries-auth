package com.habittracker.authclient.env;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.Map;
import java.util.Properties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.env.PropertySource;
import org.springframework.core.env.StandardEnvironment;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.GetParameterRequest;
import software.amazon.awssdk.services.ssm.model.GetParameterResponse;
import software.amazon.awssdk.services.ssm.model.Parameter;

class SsmSecretsEnvironmentPostProcessorTest {
    private final SsmSecretsEnvironmentPostProcessor postProcessor =
            new SsmSecretsEnvironmentPostProcessor();

    @Test
    @DisplayName("parsePropertyPaths reads a newline-delimited property-name=path blob")
    void parsePropertyPathsReadsBlob() {
        Properties parsed =
                SsmSecretsEnvironmentPostProcessor.parsePropertyPaths(
                        "jwt.access-secret=/services/auth/jwt/access-secret\n"
                                + "jwt.refresh-secret=/services/auth/jwt/refresh-secret");

        assertThat(parsed.getProperty("jwt.access-secret"))
                .isEqualTo("/services/auth/jwt/access-secret");
        assertThat(parsed.getProperty("jwt.refresh-secret"))
                .isEqualTo("/services/auth/jwt/refresh-secret");
    }

    @Test
    @DisplayName(
            "resolveAll fetches each path with decryption and keys the result by property name")
    void resolveAllFetchesEachParameter() {
        Properties propertyPaths = new Properties();
        propertyPaths.setProperty("jwt.access-secret", "/services/auth/jwt/access-secret");
        SsmClient ssmClient = mock(SsmClient.class);
        when(ssmClient.getParameter(
                        GetParameterRequest.builder()
                                .name("/services/auth/jwt/access-secret")
                                .withDecryption(true)
                                .build()))
                .thenReturn(
                        GetParameterResponse.builder()
                                .parameter(Parameter.builder().value("resolved-secret").build())
                                .build());

        Map<String, Object> resolved =
                SsmSecretsEnvironmentPostProcessor.resolveAll(propertyPaths, ssmClient);

        assertThat(resolved).containsExactly(Map.entry("jwt.access-secret", "resolved-secret"));
    }

    @Test
    @DisplayName("postProcessEnvironment is a no-op when SSM_BACKED_PROPERTIES is unset")
    void noOpWhenSourceEnvVarAbsent() {
        StandardEnvironment environment = new StandardEnvironment();
        int sourceCountBefore = environment.getPropertySources().size();

        postProcessor.postProcessEnvironment(environment, mock(SpringApplication.class));

        assertThat(environment.getPropertySources()).hasSize(sourceCountBefore);
    }

    @Test
    @DisplayName(
            "postProcessEnvironment resolves every path and adds them as the highest-priority source")
    void postProcessEnvironmentAddsResolvedPropertySource() {
        SsmClient ssmClient = mock(SsmClient.class);
        when(ssmClient.getParameter(any(GetParameterRequest.class)))
                .thenReturn(
                        GetParameterResponse.builder()
                                .parameter(Parameter.builder().value("resolved-secret").build())
                                .build());
        SsmSecretsEnvironmentPostProcessor postProcessorWithFakeClient =
                new SsmSecretsEnvironmentPostProcessor(region -> ssmClient);

        StandardEnvironment environment =
                environmentWith(
                        Map.of(
                                "aws.region", "eu-central-1",
                                "SSM_BACKED_PROPERTIES",
                                        "jwt.access-secret=/services/auth/jwt/access-secret"));

        postProcessorWithFakeClient.postProcessEnvironment(
                environment, mock(SpringApplication.class));

        PropertySource<?> first = environment.getPropertySources().iterator().next();
        assertThat(first.getName()).isEqualTo("ssmBackedSecrets");
        assertThat(first.getProperty("jwt.access-secret")).isEqualTo("resolved-secret");
        assertThat(environment.getProperty("jwt.access-secret")).isEqualTo("resolved-secret");
    }

    @Test
    @DisplayName("a real SsmClient is never touched when the source env var is absent")
    void neverConstructsClientWhenNoOp() {
        SsmClient ssmClient = mock(SsmClient.class);
        SsmSecretsEnvironmentPostProcessor postProcessorWithFakeClient =
                new SsmSecretsEnvironmentPostProcessor(region -> ssmClient);

        postProcessorWithFakeClient.postProcessEnvironment(
                new StandardEnvironment(), mock(SpringApplication.class));

        verifyNoInteractions(ssmClient);
    }

    private static StandardEnvironment environmentWith(Map<String, Object> properties) {
        StandardEnvironment environment = new StandardEnvironment();
        MutablePropertySources sources = environment.getPropertySources();
        sources.addFirst(new MapPropertySource("test", properties));
        return environment;
    }
}
