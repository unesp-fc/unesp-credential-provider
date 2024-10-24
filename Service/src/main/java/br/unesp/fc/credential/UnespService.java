package br.unesp.fc.credential;

import br.unesp.fc.credential.vo.AlunoGraduacaoVO;
import br.unesp.fc.credential.vo.AlunoStrictoSensuVO;
import br.unesp.fc.credential.vo.ServidorPublicoVO;
import java.util.Arrays;
import java.util.concurrent.CompletableFuture;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

@Service
@Slf4j
public class UnespService {

    @Value("${app.unesp-uri}")
    private String unespUri;

    private final RestClient restClient;

    public UnespService() {
        restClient = RestClient.builder()
                .build();
    }

    @Async
    public CompletableFuture<ServidorPublicoVO> buscarServidorPublico(String id) {
        log.debug("buscarServidorPublico: {}", id);
        return CompletableFuture.completedFuture(restClient.get()
                .uri(unespUri + "/rh/api/v2/servidoresPublico/identificacaoCentralAcesso::{id}", id)
                .retrieve()
                .body(ServidorPublicoVO[].class))
                .thenApply((servidores) -> {
                    var servidor = Arrays.stream(servidores).filter(ServidorPublicoVO::getAtivo)
                            .findAny();
                    if (servidor.isPresent()) {
                        log.debug("buscarServidorPublico: {} {}", id, servidor.get().getMatricula());
                        buscarServidorPublicoLotacao(servidor.get().getIdLotacaoPrestacao()).thenAccept(l -> {
                            servidor.get().setLotacaoPrestacao(l);
                            buscarServidorPublicoUnidade(l.getIdUnidadeUniversitaria()).thenAccept(u -> l.setUnidadeUniversitaria(u)).join();
                        }).join();
                    } else {
                        log.debug("buscarServidorPublico: Não encontrado {}", id);
                    }
                    return servidor.orElse(null);
                });
    }

    @Async
    public CompletableFuture<ServidorPublicoVO.LotacaoVO> buscarServidorPublicoLotacao(Long id) {
        log.debug("buscarServidorPublicoLotacao: {}", id);
        return CompletableFuture.completedFuture(restClient.get()
                .uri(unespUri + "/rh/api/v2/lotacoes/{id}", id)
                .retrieve()
                .body(ServidorPublicoVO.LotacaoVO.class));
    }

    @Async
    public CompletableFuture<ServidorPublicoVO.UnidadeUniversitariaVO> buscarServidorPublicoUnidade(Long id) {
        log.debug("buscarServidorPublicoUnidade: {}", id);
        return CompletableFuture.completedFuture(restClient.get()
                .uri(unespUri + "/rh/api/v2/unidadeUniversitaria/{id}", id)
                .retrieve()
                .body(ServidorPublicoVO.UnidadeUniversitariaVO[].class))
                .thenApply(l -> l.length > 0 ? l[0] : null);
    }

    @Async
    public CompletableFuture<AlunoGraduacaoVO> buscarAlunoGraduacao(String id) {
        log.debug("buscarAlunoGraduacao: {}", id);
        try {
            return CompletableFuture.completedFuture(restClient.get()
                    .uri(unespUri + "/academico/api/v2/alunosGraduacao/pesquisa?identificacao={id}&somenteMatriculado=true", id)
                    .retrieve()
                    .body(AlunoGraduacaoVO[].class))
                    .thenApply(alunos -> {
                        if (alunos.length == 0) {
                            return null;
                        }
                        var curso = buscarAlunoGraduacaoCurso(alunos[0].getIdCurso()).thenAccept(c -> alunos[0].setCursoVO(c));
                        var unidade = buscarAlunoGraduacaoUnidade(alunos[0].getIdUnidadeUniversitaria()).thenAccept(u -> alunos[0].setUnidadeVO(u));
                        CompletableFuture.allOf(curso, unidade).join();
                        return alunos[0];
                    });
        } catch (HttpClientErrorException.NotFound ex) {
            log.debug("buscarAlunoGraduacao: Não encontrado {}", id);
            return CompletableFuture.completedFuture(null);
        }
    }

    @Async
    private CompletableFuture<AlunoGraduacaoVO.CursoVO> buscarAlunoGraduacaoCurso(Long id) {
        log.debug("buscarAlunoGraduacaoCurso: {}", id);
        return CompletableFuture.completedFuture(restClient.get()
                .uri(unespUri + "/academico/api/v2/cursos/{id}", id)
                .retrieve()
                .body(AlunoGraduacaoVO.CursoVO.class));
    }

    @Async
    private CompletableFuture<AlunoGraduacaoVO.UnidadeVO> buscarAlunoGraduacaoUnidade(Long id) {
        log.debug("buscarAlunoGraduacaoUnidade: {}", id);
        return CompletableFuture.completedFuture(restClient.get()
                .uri(unespUri + "/academico/api/v2/unidadesUniversitarias/{id}", id)
                .retrieve()
                .body(AlunoGraduacaoVO.UnidadeVO.class));
    }

    @Async
    public CompletableFuture<AlunoStrictoSensuVO> buscarAlunoPosGraduacao(String id) {
        log.debug("buscarAlunoPosGraduacao: {}", id);
        return CompletableFuture.completedFuture(restClient.get()
                .uri(unespUri + "/posgraduacao/api/v1/alunoStrictoSensu/identificacao::{id}", id)
                .retrieve()
                .body(AlunoStrictoSensuVO[].class))
                .thenApply(alunos -> {
                    var aluno = Arrays.stream(alunos).filter(a -> AlunoStrictoSensuVO.Situacao.MATRICULADO.equals(a.getSituacao()))
                            .findAny();
                    if (aluno.isPresent()) {
                        log.debug("buscarAlunoPosGraduacao: {} {}", id, aluno.get().getRegistroAcademico());
                        var programa = buscarAlunoPosGraduacaoPrograma(aluno.get().getIdPrograma()).thenAccept(p -> aluno.get().setProgramaVO(p));
                        var unidade = buscarAlunoPosGraduacaoUnidade(aluno.get().getIdUnidadeUniversitaria()).thenAccept(u -> aluno.get().setUnidadeVO(u));
                        CompletableFuture.allOf(programa, unidade).join();
                    } else {
                        log.debug("buscarAlunoPosGraduacao: Não encontrado {}", id);
                    }
                    return aluno.orElse(null);
                });
    }

    @Async
    public CompletableFuture<AlunoStrictoSensuVO.ProgramaVO> buscarAlunoPosGraduacaoPrograma(Long id) {
        log.debug("buscarAlunoPosGraduacaoPrograma: {}", id);
        return CompletableFuture.completedFuture(restClient.get()
                .uri(unespUri + "/posgraduacao/api/v1/programas/{id}", id)
                .retrieve()
                .body(AlunoStrictoSensuVO.ProgramaVO.class));
    }

    @Async
    private CompletableFuture<AlunoStrictoSensuVO.UnidadeVO> buscarAlunoPosGraduacaoUnidade(Long id) {
        log.debug("buscarAlunoPosGraduacaoUnidade: {}", id);
        return CompletableFuture.completedFuture(restClient.get()
                .uri(unespUri + "/posgraduacao/api/v1/unidadesUniversitarias/{id}", id)
                .retrieve()
                .body(AlunoStrictoSensuVO.UnidadeVO.class));
    }

}
