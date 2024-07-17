package oauth2.authorization.server.mapper;

import oauth2.authorization.server.entity.Client;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
public class RegisteredClientMapper {

    // not clean code, just simplified example to carry on
    public Client mapRegisteredClientToClient(RegisteredClient registeredClient) {
        Client client = new Client();

        client.setClientId(registeredClient.getClientId());
        client.setSecret(registeredClient.getClientSecret());
        client.setRedirectUri(
                registeredClient.getRedirectUris().stream().findAny().get()
        );
        client.setScope(
                registeredClient.getScopes().stream().findAny().get()
        );
        client.setAuthMethod(
                registeredClient.getClientAuthenticationMethods().stream().findAny().get().getValue()
        );
        client.setGrantType(
                registeredClient.getAuthorizationGrantTypes().stream().findAny().get().getValue()
        );

        return client;
    }

    public RegisteredClient mapClientToRegisteredClient(Client client) {
        return RegisteredClient
                .withId(String.valueOf(client.getId()))
                .clientId(client.getClientId())
                .clientSecret(client.getSecret())
                .scope(client.getScope())
                .redirectUri(client.getRedirectUri())
                .clientAuthenticationMethod(new ClientAuthenticationMethod(client.getAuthMethod()))
                .authorizationGrantType(new AuthorizationGrantType(client.getGrantType()))
                // for client application
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .tokenSettings(TokenSettings
                        .builder()
                        .accessTokenTimeToLive(Duration.ofSeconds(900))
//                        .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                        .build())
                .build();
    }

}
