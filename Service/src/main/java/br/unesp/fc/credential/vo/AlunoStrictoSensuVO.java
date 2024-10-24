package br.unesp.fc.credential.vo;

import java.io.Serializable;
import lombok.Data;

@Data
public class AlunoStrictoSensuVO implements Serializable {

    private Long idAlunoStrictoSensuRegulamento;
    private String nome;
    private String sexo;
    private String email;
    private String cpf;
    private Long idCurso;
    private String curso;
    private Long idPrograma;
    private String programa;
    private String inicioCurso;
    private String tipoAluno;
    private Situacao situacao;
    private String registroAcademico;
    private Long idUnidadeUniversitaria;

    // Vínculos
    private ProgramaVO programaVO;
    private UnidadeVO unidadeVO;

    public enum Situacao {
        SUSPENSO,
        FORMADO,
        DESLIGADO,
        MATRICULADO
    }

    @Data
    public static class ProgramaVO implements Serializable {

        private Long id;
        private String nome;
        private String sigla;

    }

    @Data
    public static class UnidadeVO implements Serializable {

        private Integer id;
        private String sigla;
        private String nome;
        private String campus;

    }

}
