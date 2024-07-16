package oauth2.authorization.server.service;

import lombok.RequiredArgsConstructor;
import oauth2.authorization.server.entity.Client;
import oauth2.authorization.server.exception.ClientNotFoundException;
import oauth2.authorization.server.mapper.RegisteredClientMapper;
import oauth2.authorization.server.repository.ClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
@Service
@RequiredArgsConstructor
public class CustomClientService implements RegisteredClientRepository {
    private final ClientRepository clientRepository;
    private final RegisteredClientMapper registeredClientMapper;

    @Override
    public void save(RegisteredClient registeredClient) {
        clientRepository.save(registeredClientMapper.mapRegisteredClientToClient(registeredClient));
    }

    @Override
    public RegisteredClient findById(String id) throws ClientNotFoundException {
        Client client = clientRepository.findById(Long.valueOf(id))
                .orElseThrow(
                        () -> new ClientNotFoundException(String.format("Client with id = %s not found", id)
                        ));
        System.out.println(client);
        System.out.println(registeredClientMapper.mapClientToRegisteredClient(client));
        return registeredClientMapper.mapClientToRegisteredClient(client);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Client client = clientRepository.findByClientId(clientId)
                .orElseThrow(
                        () -> new ClientNotFoundException(String.format("Client with client_id = %s not found", clientId)
                        ));
        System.out.println(client);
        System.out.println(registeredClientMapper.mapClientToRegisteredClient(client));
        return registeredClientMapper.mapClientToRegisteredClient(client);
    }
}
