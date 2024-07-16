package oauth2.authorization.server.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "clients")
@Getter
@Setter
public class Client {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    private String clientId;

    private String secret;

    private String redirectUri;

    private String scope;

    private String authMethod;

    private String grantType;

    @Override
    public String toString() {
        return "Client{" +
                "id=" + id +
                ", clientId='" + clientId + '\'' +
                ", secret='" + secret + '\'' +
                ", redirectUri='" + redirectUri + '\'' +
                ", scope='" + scope + '\'' +
                ", authMethod='" + authMethod + '\'' +
                ", grantType='" + grantType + '\'' +
                '}';
    }
}
