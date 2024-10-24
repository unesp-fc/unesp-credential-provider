
package br.unesp.fc.credential.vo;

import java.io.Serializable;
import lombok.Data;

@Data
public class ServidorPublicoVO implements Serializable {

    private Long id;
    private String matricula;
    private String nome;
    private String cpf;
    private String email;
    private Long idLotacaoPrestacao;
    private Boolean aposentado;
    private Boolean ativo;
    private LotacaoVO lotacaoPrestacao;

    @Data
    public static class LotacaoVO implements Serializable {

        private Long id;
        private Long idUnidadeUniversitaria;
        private String sigla;
        private String nome;
        private UnidadeUniversitariaVO unidadeUniversitaria;

    }

    @Data
    public static class UnidadeUniversitariaVO implements Serializable {

        private Long id;
        private String sigla;
        private String nome;
        private String campus;

    }

}
