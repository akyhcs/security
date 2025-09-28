// src/main/java/com/example/security/OAuth2ClientFromFileConfig.java
package com.example.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.registration.*;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

@Configuration
public class OAuth2ClientFromFileConfig {

  // ---- Supply these file paths however you like ----
  // e.g. -Dthirdparty.clientIdPath=/etc/secrets/client_id.txt
  //       -Dthirdparty.clientSecretPath=/etc/secrets/client_secret.txt
  //       -Dthirdparty.tokenUri=https://auth.example.com/oauth2/token
  private final String clientIdPath     = System.getProperty("thirdparty.clientIdPath", "/etc/secrets/client_id.txt");
  private final String clientSecretPath = System.getProperty("thirdparty.clientSecretPath", "/etc/secrets/client_secret.txt");
  private final String tokenUri         = System.getProperty("thirdparty.tokenUri", "https://auth.example.com/oauth2/token");
  // optional: scopes via -Dthirdparty.scopes="read,write"
  private final List<String> scopes     = List.of(System.getProperty("thirdparty.scopes", "").split(","))
                                               .stream().filter(s -> !s.isBlank()).toList();

  @Bean
  public ClientRegistrationRepository clientRegistrationRepository() {
    String clientId     = readTrim(clientIdPath);
    String clientSecret = readTrim(clientSecretPath);

    ClientRegistration.Builder b = ClientRegistration
        .withRegistrationId("thirdparty")
        .clientId(clientId)
        .clientSecret(clientSecret)
        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
        .tokenUri(tokenUri);

    if (!scopes.isEmpty()) b.scope(scopes);

    ClientRegistration reg = b.build();
    return new InMemoryClientRegistrationRepository(reg);
  }

  @Bean
  public OAuth2AuthorizedClientService authorizedClientService(ClientRegistrationRepository repo) {
    return new InMemoryOAuth2AuthorizedClientService(repo);
  }

  @Bean
  public OAuth2AuthorizedClientManager authorizedClientManager(
      ClientRegistrationRepository repo,
      OAuth2AuthorizedClientService service) {

    var provider = OAuth2AuthorizedClientProviderBuilder.builder()
        .clientCredentials()
        .build();

    var manager = new AuthorizedClientServiceOAuth2AuthorizedClientManager(repo, service);
    manager.setAuthorizedClientProvider(provider);
    return manager;
  }

  private static String readTrim(String path) {
    try {
      return Files.readString(Path.of(path)).trim(); // trims newlines at EOF
    } catch (Exception e) {
      throw new IllegalStateException("Failed to read secret from: " + path, e);
    }
  }
}
