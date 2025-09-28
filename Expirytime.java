@Service
@RequiredArgsConstructor
public class OAuth2TokenService {
  private final OAuth2AuthorizedClientManager manager;

  public record TokenInfo(String token, Instant issuedAt, Instant expiresAt, Duration ttl) {}

  public TokenInfo getThirdPartyTokenInfo() {
    var req = OAuth2AuthorizeRequest.withClientRegistrationId("thirdparty")
        .principal("service-account")
        .build();

    var client = manager.authorize(req);
    if (client == null || client.getAccessToken() == null) {
      throw new IllegalStateException("Could not obtain access token");
    }

    var at = client.getAccessToken();
    Instant issued = at.getIssuedAt();       // may be null on some providers
    Instant expires = at.getExpiresAt();     // what you’re asking for
    Duration ttl = (expires != null) ? Duration.between(Instant.now(), expires) : null;

    return new TokenInfo(at.getTokenValue(), issued, expires, ttl);
  }
}
