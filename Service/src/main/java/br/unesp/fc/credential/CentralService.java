package br.unesp.fc.credential;

import br.unesp.fc.credential.vo.OAuth2Error;
import br.unesp.fc.credential.vo.TokenVO;
import br.unesp.fc.credential.vo.UsuarioVO;
import java.util.concurrent.CompletableFuture;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

@Service
@Slf4j
public class CentralService {

    private final RestClient restClient;
    private final ClientRegistration client;

    public CentralService(ClientRegistrationRepository clientRegistrationRepository) {
        client = clientRegistrationRepository.findByRegistrationId("central");
        restClient = RestClient.builder()
                .build();
    }

    @Async
    public CompletableFuture<TokenVO> login(String username, String password) {
        if (username.contains("@")) {
            username = username.split("@", 2)[0];
        }
        log.debug("Login: {}", username);
        MultiValueMap<String, String> data = new LinkedMultiValueMap<>();
        data.add("grant_type", "password");
        data.add("username", username);
        data.add("password", password);
        try {
            return CompletableFuture.completedFuture(restClient.post()
                    .uri(client.getProviderDetails().getTokenUri())
                    .headers(h -> h.setBasicAuth(client.getClientId(), client.getClientSecret()))
                    .body(data)
                    .retrieve()
                    .body(TokenVO.class));
        } catch (HttpClientErrorException.BadRequest ex) {
            try {
                var error = ex.getResponseBodyAs(OAuth2Error.class);
                if ("invalid_grant".equals(error.getError())) {
                    log.debug("Login inválido: {}", username);
                    return CompletableFuture.completedFuture(null);
                }
            } catch (RestClientException e) {
                log.error("Erro lendo resposta de erro da Central", ex);
            }
            return CompletableFuture.failedFuture(ex);
        } catch (HttpClientErrorException ex) {
            log.error("Erro consultando a Central", ex);
            return CompletableFuture.failedFuture(ex);
        }
    }

    public UsuarioVO getUserLogin(TokenVO token) {
        return getUserLogin(token.getAccessToken());
    }

    public UsuarioVO getUserLogin(String accessToken) {
        return restClient.get()
                .uri(client.getProviderDetails().getUserInfoEndpoint().getUri())
                .headers(h -> h.setBearerAuth(accessToken))
                .retrieve()
                .body(UsuarioVO.class);
    }

}
