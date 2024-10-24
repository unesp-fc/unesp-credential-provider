package br.unesp.fc.credential.vo;

import java.io.Serializable;
import lombok.Data;

@Data
public class AlunoGraduacaoVO implements Serializable {

    private Long id;
    private Long idCurso;
    private Long idUnidadeUniversitaria;

    private String registroAcademico;
    private String situacaoAtual;
    private Boolean matriculado;
    private String nome;
    private String nomeSocial;
    private String cpf;

    private String email;

    private CursoVO cursoVO;
    private UnidadeVO unidadeVO;

    @Data
    public static class CursoVO implements Serializable {

        private Long id;
        private Long idUnidadeUniversitaria;
        private String sigla;
        private String nome;
        private String nomeAbreviado;

    }

    @Data
    public static class UnidadeVO implements Serializable {

        private Integer id;
        private String sigla;
        private String nome;
        private String campus;

    }

}
